namespace IdentityServerAsp.Models
{
    public class ForgotPasswordUserNameViewModel
    {
        public string CallbackUrl { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
    }
}