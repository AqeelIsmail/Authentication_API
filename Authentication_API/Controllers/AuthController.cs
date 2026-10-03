using Authentication_API;
using Authentication_API.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

[ApiController]
[Route("api/[controller]")]
public class AuthController : Controller
{  
    //https://andrewlock.net/exploring-the-asp-net-core-identity-passwordhasher/

    private readonly AppDbContext _context;

    //PasswordHashed requires a class object to be passed to it on which the hashing will be done
    private readonly PasswordHasher<User> _hasher = new(); //in built salt and hasher 

    public AuthController(AppDbContext context)
    {
        _context = context;
    }

    [HttpPost("register")]
    public IActionResult Register(RegisterDto dto) //uses the data object for register (email, password and role)
    {
        //actual User object is created using the user input from RegisterDto
        var newUser = new User { Email = dto.Email, Role = dto.Role };
        newUser.PasswordHash = _hasher.HashPassword(newUser, dto.Password);//using inbuilt hashing method hash the password

        _context.Users.Add(newUser); //store the hashed password to the db
        _context.SaveChanges();
        return Ok("Registered");
    }

    /* Step 1: 
     * Runs when the client sends a request to this endpoint 
     * This endpoint checks if the password sent is correct and creates a cookie on line 68
     *  */
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        //looks up the user by email. If nobody has the email return 401 status code
        var user = _context.Users.FirstOrDefault(u => u.Email == dto.Email);
        if (user == null)
        { 
            return Unauthorized();
        }

        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, dto.Password);

        if (result == PasswordVerificationResult.Failed) 
        { 
            return Unauthorized(); 
        }
        /* Step 2: Claim created
         Claim is a single labeled fact about the user - Key value pair
         Here we record 2 facts: Name/email and the persons role 
         This is a bag of facts about this one login */
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Email),
            new Claim(ClaimTypes.Role, user.Role)
        };

        /* Step 3: Bundles the claims of the user in an object, holding info about who this person is
         * Later on when a logged in persons role needs to be checked, this will be referred to */
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        /* Step 4: This makes the API server attach a "Set-Cookie" header to its HTTP response
         * and create a cookie with the encrypted details of the user */
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        return Ok("Logged in");
    }

    [HttpPost("logout")] //clears the users cookie
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok("Logged out");
    }
}