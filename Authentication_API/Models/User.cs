using Microsoft.AspNetCore.Identity;

namespace Authentication_API
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string Role { get; set; } // "Student" or "teacher"
    }
}
