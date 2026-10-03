namespace Authentication_API.Models
{
    //This is the data that the user will interact with 
    public class RegisterDto
    {
        public string Email { get; set; }
        public string Password { get; set; } //password123
        public string Role { get; set; } // "Student" or "Teacher"
    }
}
