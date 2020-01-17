using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Configuration.Version1;
using Telligent.Evolution.Extensibility.UI.Version1;

using IPluginConfiguration = Telligent.Evolution.Extensibility.Version2.IPluginConfiguration;
using NotImplementedException = System.NotImplementedException;

namespace CommunityUserThrottle
{
	public class LoginThrottleService 
	{
		DateTime _lastCleanupDate = DateTime.UtcNow.Add(new TimeSpan(0, 0, _cleanupMinutesInterval));
		DateTime _lastFailedLoginCleanupDate = DateTime.UtcNow.Add(new TimeSpan(0, 0, _cleanupMinutesInterval));
		internal string EmailAddresses;
		static int _cleanupMinutesInterval = 5;
		private int _maxNumberOfLoginAttempts = 15;
		TimeSpan _stale = new TimeSpan(0, 1, 0, 0);
		internal bool SendEmail;

		readonly ConcurrentDictionary<string, LoginAttemptsSummary> _loginAttempts = new ConcurrentDictionary<string, LoginAttemptsSummary>();
		readonly ConcurrentDictionary<string, FailedLoginAttempt> _failedLoginAttempts = new ConcurrentDictionary<string, FailedLoginAttempt>();
		internal TimeSpan FailedLoginAttemptsWindow { get; set; } = new TimeSpan(0, 12, 0, 0);
		internal int MaximumNumberOfFailedLoginAttemptsForSendingEmail { get; set; } = 50;
		internal TimeSpan TimeToThrottle { get; set; } = new TimeSpan(0, 0, 15, 0);
		internal int MaximumNumberOfLoginAttempts
		{
			get => _maxNumberOfLoginAttempts;
			set => _maxNumberOfLoginAttempts = value < 0 ? 10 : value;
		} 

		public bool IsCurrentlyThrottled(string ip)
		{
			return (!string.IsNullOrEmpty(ip) && _loginAttempts != null && _loginAttempts.ContainsKey(ip) && _loginAttempts[ip].ThrottledUntilTime > DateTime.UtcNow);
		}

		public void LogFailedAttempt(string ip)
		{
			var key = $"{ip}-{DateTime.UtcNow.Ticks}";
			try
			{
				if (!_failedLoginAttempts.ContainsKey(key))
					_failedLoginAttempts[key] = new FailedLoginAttempt() { AttemptDate = DateTime.UtcNow, IP = ip };
				SendEmailIfOverLimit(MaximumNumberOfFailedLoginAttemptsForSendingEmail);
			}
			catch (Exception ex)
			{
				Telligent.Evolution.Extensibility.Apis.Get<IEventLog>().Write($"Error while logging failed login attempt: '{ex}')."
					, new EventLogEntryWriteOptions() { Category = "LoginThrottling", EventType = "Information" });
			}
		}

		void SendEmailIfOverLimit(int maxNumberOfFailedLogins)
		{
			CleanupFailedLoginsForEmailCheck();

			if (!SendEmail || string.IsNullOrEmpty(EmailAddresses))
				return;

			var count = _failedLoginAttempts.Count;
			var copy = _failedLoginAttempts.Values.ToArray();

			var sortedValuesByTime = copy.OrderBy(v => v.AttemptDate);
			if (count > maxNumberOfFailedLogins)
			{
				var email = Telligent.Evolution.Extensibility.Apis.Get<ISendEmail>();
				var siteInfo = Telligent.Evolution.Extensibility.Apis.Get<IInfoResults>();
				var emailOptions = new SendEmailOptions
				{
					Body = $"There were {count} failed logins in the past '{FailedLoginAttemptsWindow.Hours}' hours (First={sortedValuesByTime.First().AttemptDate.ToLocalTime()}," +
					       $" Last{sortedValuesByTime.Last().AttemptDate.ToLocalTime()}). This is over the threshold of {maxNumberOfFailedLogins} set in the configuration. The counter will be reset.",
					Subject = $"[{siteInfo.Get().SiteName}] : Excessive Failed Login Attempts - Count={count}",
					ToEmail = EmailAddresses
				};
				var emails = EmailAddresses.Split(new[] {';'}, StringSplitOptions.RemoveEmptyEntries);
				foreach (var e in emails)
				{
					emailOptions.ToEmail = e.Trim();
					email.Send(emailOptions);
				}
				_failedLoginAttempts.Clear();
			}
		}

		public bool CheckAndTrackLoginAttempt(string ip)
		{
			if (string.IsNullOrEmpty(ip))
				ip = "null-IP";

			try
			{
				if (!_loginAttempts.ContainsKey(ip))
					_loginAttempts[ip] = new LoginAttemptsSummary();

				var loginSummary = _loginAttempts[ip];

				if (loginSummary.ThrottledUntilTime > DateTime.UtcNow)
					return false;

				loginSummary.AddNewAttempt();
				//they are past the ban
				if (loginSummary.ThrottledUntilTime > DateTime.MinValue && loginSummary.ThrottledUntilTime < DateTime.UtcNow)
					loginSummary.ThrottledUntilTime = DateTime.MinValue;
				else if (loginSummary.FirstAttemptDate > DateTime.MinValue && loginSummary.NumberOfAttempts > MaximumNumberOfLoginAttempts)
				{
					loginSummary.ThrottledUntilTime = DateTime.UtcNow.Add(TimeToThrottle);
					Telligent.Evolution.Extensibility.Apis.Get<IEventLog>().Write(
						$"Throttling IP '{ip}' until '{loginSummary.ThrottledUntilTime.ToLocalTime()}' ({TimeToThrottle.Minutes} minutes) due to too many login attempts ({loginSummary.NumberOfAttempts})."
						, new EventLogEntryWriteOptions() { Category = "LoginThrottling", EventType = "Information" });
					loginSummary.ResetAttempts();
					return false;
				}
				Cleanup();
			}
			catch
			{
				//throw;
			}
			return true;
		}

		void Cleanup()
		{
			if (DateTime.UtcNow.Subtract(_lastCleanupDate).Minutes > _cleanupMinutesInterval)
			{
				foreach (var la in _loginAttempts.Where(l => (!IsCurrentlyThrottled(l.Key) && l.Value.LastAttemptDate > DateTime.MinValue && DateTime.UtcNow.Subtract(l.Value.LastAttemptDate) > _stale)))
				{
					_loginAttempts.TryRemove(la.Key, out var ignored);
				}
				_lastCleanupDate = DateTime.UtcNow;
			}
		}

		void CleanupFailedLoginsForEmailCheck()
		{
			if (DateTime.UtcNow.Subtract(_lastFailedLoginCleanupDate).Minutes > _cleanupMinutesInterval)
			{
				foreach (var la in _failedLoginAttempts.Where(l => (l.Value.AttemptDate < DateTime.UtcNow.Subtract(FailedLoginAttemptsWindow))))
				{
					_failedLoginAttempts.TryRemove(la.Key, out var ignored);
				}
				_lastFailedLoginCleanupDate = DateTime.UtcNow;
			}
		}

	}

	public class LoginThrottleExtension : IScriptedContentFragmentExtension,
		Telligent.Evolution.Extensibility.Version2.IConfigurablePlugin
	{
		static LoginThrottleService _throttleService;
		public string ExtensionName => "verint_v1_throttle";
		public object Extension => _throttleService;

		public void Initialize()
		{ 		
			if (_throttleService == null)
				_throttleService = new LoginThrottleService();
			_throttleService.MaximumNumberOfLoginAttempts = Configuration.GetInt("MaxNumberOfFailedAttempts").GetValueOrDefault();
			_throttleService.TimeToThrottle = new TimeSpan(0, 0, Configuration.GetInt("ThrottleMinutes").GetValueOrDefault(), 5);
			_throttleService.SendEmail =  Configuration.GetBool("SendEmailOnExcessiveLoginFailures").GetValueOrDefault(false);
			_throttleService.EmailAddresses = Configuration.GetString("EmailAddresses");
			_throttleService.MaximumNumberOfFailedLoginAttemptsForSendingEmail = Configuration.GetInt("NumberOfFailedLoginAttemptsBeforeEmail").GetValueOrDefault();
			_throttleService.FailedLoginAttemptsWindow = new TimeSpan(0, Configuration.GetInt("FailedLoginAttemptsHourEmailWindow").GetValueOrDefault(), 0, 0);
		}

		public string Name => "User Authentication Throttle Extension ($verint_v1_throttle)";
		public string Description => "API used to check for login abuse.";
		
		#region V2.IConfigurablePlugin Members

		protected IPluginConfiguration Configuration { get; private set; }

		public void Update(IPluginConfiguration configuration)
		{
			Configuration = configuration;
		}

		public PropertyGroup[] ConfigurationOptions
		{
			get
			{
				var groups = new[]
				{
					new PropertyGroup
					{
						Id = "options",
						LabelText = "Options",
						OrderNumber = 0
					},
				};

				groups[0].Properties.Add(new Property
				{
					Id = "MaxNumberOfFailedAttempts",
					LabelText = "Maximum number of attempts before throttling",
					DataType = "Int",
					OrderNumber = 0,
					DefaultValue = "10",
					DescriptionText = "After this number of failed attempts, the offending IP will not be allow to login anymore."
				});
				groups[0].Properties.Add(new Property
				{
					Id = "ThrottleMinutes",
					LabelText = "Minutes to throttle",
					DataType = "Int",
					OrderNumber = 1,
					DefaultValue = "10",
					DescriptionText = "The number of minutes to throttle/block this IP from attempting to login."
				});
				groups[0].Properties.Add(new Property
				{
					Id = "SendEmailOnExcessiveLoginFailures",
					LabelText = "Send Email",
					DataType = "Bool",
					OrderNumber = 2,
					DefaultValue = "true",
					DescriptionText = "Send email if there are excessive number of logins failures."
				});
				groups[0].Properties.Add(new Property
				{
					Id = "FailedLoginAttemptsHourEmailWindow",
					LabelText = "Hour(s) window for emailing failed throttle",
					DataType = "Int",
					OrderNumber = 3,
					DefaultValue = "12",
					DescriptionText = "The window of hours to evaluate for the number of failed attempts before sending email. If the configured number of failures happen in this hour(s) window, an email will be sent."
				});
				groups[0].Properties.Add(new Property
				{
					Id = "NumberOfFailedLoginAttemptsBeforeEmail",
					LabelText = "Number of failed email attempts before sending email",
					DataType = "Int",
					OrderNumber = 4,
					DefaultValue = "50",
					DescriptionText = "The number of failed attempts that must occur within the window before an email is sent."
				});
				groups[0].Properties.Add(new Property
				{
					Id = "EmailAddresses",
					LabelText = "Emails addresses (separated by semicolons). Ex. 'admin@localhost.com;another@localhost.com'",
					DataType = "String",
					OrderNumber = 5,
					DefaultValue = ""
				});

				return groups;
			}
		}

		#endregion
	}

	class FailedLoginAttempt
	{
		public DateTime AttemptDate { get; set; }
		public string IP { get; set; }
	}

	class LoginAttemptsSummary
	{
		public int NumberOfAttempts { get; private set; }
		public DateTime ThrottledUntilTime { get; set; }
		public DateTime FirstAttemptDate { get; set; }
		public DateTime LastAttemptDate { get; set; }

		public void AddNewAttempt()
		{
			if (FirstAttemptDate == DateTime.MinValue)
				FirstAttemptDate = DateTime.UtcNow;
			LastAttemptDate = DateTime.UtcNow;
			NumberOfAttempts++;
		}

		public void ResetAttempts()
		{
			NumberOfAttempts = 0;
			FirstAttemptDate = DateTime.UtcNow;
		}

		public LoginAttemptsSummary()
		{
			ThrottledUntilTime = DateTime.MinValue;
		}
	}

}
