using Authentication_API.Controllers;
using Authentication_API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System;
using System.Collections.Generic;
using System.Text;

namespace Authentication_API.Tests
{
    public class AuthControllerTests
    {
        // Creates a separate in-memory database for each test
        private AppDbContext CreateDbContext()
        {
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;

            return new AppDbContext(options);
        }

        // Sets up HttpContext so that Login() can use cookie authentication
        //private void SetupHttpContext(AuthController controller)
        //{
        //    var services = new ServiceCollection();

        //    services
        //        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        //        .AddCookie();

        //    var serviceProvider = services.BuildServiceProvider();

        //    var httpContext = new DefaultHttpContext
        //    {
        //        RequestServices = serviceProvider
        //    };

        //    controller.ControllerContext = new ControllerContext
        //    {
        //        HttpContext = httpContext
        //    };
        //}

        private AuthenticationService SetupHttpContext(AuthController controller)
        {
            var AuthService = new AuthenticationService();

            var services = new ServiceCollection();

            services.AddSingleton<IAuthenticationService>(
                AuthService);

            var serviceProvider = services.BuildServiceProvider();

            var httpContext = new DefaultHttpContext
            {
                RequestServices = serviceProvider
            };

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };

            return AuthService;
        }

        [Fact]
        public void Register_ShouldCreateUser()
        {
            // Arrange
            using var context = CreateDbContext();

            var controller = new AuthController(context);

            var dto = new RegisterDto
            {
                Email = "student@test.com",
                Password = "Password123!",
                Role = "Student"
            };

            // Act
            var result = controller.Register(dto);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);

            Assert.Equal("Registered", okResult.Value);

            var user = context.Users.FirstOrDefault();

            Assert.NotNull(user);
            Assert.Equal("student@test.com", user.Email);
            Assert.Equal("Student", user.Role);

            // Password should NOT be stored as plain text
            Assert.NotEqual("Password123!", user.PasswordHash);
        }

        // Login test for correct password
        [Fact]
        public async Task Login_WithCorrectPassword_ShouldReturnOk()
        {
            // Arrange
            using var context = CreateDbContext();

            var user = new User
            {
                Email = "student@test.com",
                Role = "Student"
            };

            var hasher = new PasswordHasher<User>();

            user.PasswordHash = hasher.HashPassword(
                user,
                "Password123!"
            );

            context.Users.Add(user);
            context.SaveChanges();

            var controller = new AuthController(context);

            //// Set up HttpContext for cookie authentication
            //SetupHttpContext(controller);

            var AuthService = SetupHttpContext(controller);

            var dto = new LoginDto
            {
                Email = "student@test.com",
                Password = "Password123!"
            };

            // Act
            var result = await controller.Login(dto);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);

            //Assert.Equal("Logged in", okResult.Value);
            Assert.Equal("Logged in", okResult.Value);

            // Verify that the controller attempted to create the login session
            Assert.True(AuthService.SignInCalled);
        }

        [Fact]
        public async Task Login_WithIncorrectPassword_ShouldReturnUnauthorized()
        {
            // Arrange
            using var context = CreateDbContext();

            var user = new User
            {
                Email = "student@test.com",
                Role = "Student"
            };

            var hasher = new PasswordHasher<User>();

            user.PasswordHash = hasher.HashPassword(
                user,
                "CorrectPassword123!"
            );

            context.Users.Add(user);
            context.SaveChanges();

            var controller = new AuthController(context);

            SetupHttpContext(controller);

            var dto = new LoginDto
            {
                Email = "student@test.com",
                Password = "WrongPassword123!"
            };

            // Act
            var result = await controller.Login(dto);

            // Assert
            Assert.IsType<UnauthorizedResult>(result);
        }

        [Fact]
        public async Task Login_WithUnknownEmail_ShouldReturnUnauthorized()
        {
            // Arrange
            using var context = CreateDbContext();

            var controller = new AuthController(context);

            SetupHttpContext(controller);

            var dto = new LoginDto
            {
                Email = "doesnotexist@test.com",
                Password = "Password123!"
            };

            // Act
            var result = await controller.Login(dto);

            // Assert
            Assert.IsType<UnauthorizedResult>(result);
        }

        [Fact]
        public async Task Logout_ShouldReturnOk()
        {
            // Arrange
            using var context = CreateDbContext();

            var controller = new AuthController(context);

            var authService = SetupHttpContext(controller);

            // Act
            var result = await controller.Logout();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);

            Assert.Equal("Logged out", okResult.Value);

            // Verify that the controller attempted to sign the user out
            Assert.True(authService.SignOutCalled);
        }
    }
}
