namespace AToMS.Data.Models.AzureB2C
{
	/// <summary>
	/// Azure B2C App Settings.
	/// </summary>
	public class AzureAdB2COptions
	{
		public const string PolicyAuthenticationProperty = "Policy";

		public string ClientId { get; set; }
		public string Instance { get; set; }
		public string Domain { get; set; }
		public string EditProfilePolicyId { get; set; }
		public string SignUpSignInPolicyId { get; set; }
		public string ResetPasswordPolicyId { get; set; }
		public string CallbackPath { get; set; }
		public string DefaultPolicy => SignUpSignInPolicyId;
		public string ApplicationId { get; set; }
		public string ApplicationSecret { get; set; }
	}
}