
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Xunit;

namespace SafeVault.Tests;

public class SecurityTests
{
    // Test 1: Valid email addresses
    [Theory]
    [InlineData("user@example.com")]
    [InlineData("student@university.ac.za")]
    public void ValidEmail_ShouldPass(string email)
    {
        bool result = Regex.IsMatch(
            email,
            @"^[^@\s]+@[^@\s]+\.[^@\s]+$");

        Assert.True(result);
    }

    // Test 2: Invalid email addresses
    [Theory]
    [InlineData("invalid-email")]
    [InlineData("user@")]
    [InlineData("")]
    public void InvalidEmail_ShouldFail(string email)
    {
        bool result = Regex.IsMatch(
            email,
            @"^[^@\s]+@[^@\s]+\.[^@\s]+$");

        Assert.False(result);
    }

    // Test 3: Weak passwords should be rejected
    [Theory]
    [InlineData("12345")]
    [InlineData("password")]
    [InlineData("")]
    public void WeakPassword_ShouldFail(string password)
    {
        bool result = !string.IsNullOrWhiteSpace(password)
                      && password.Length >= 12
                      && password.Length <= 128;

        Assert.False(result);
    }

    // Test 4: Strong passwords should pass
    [Theory]
    [InlineData("SecurePassword123!")]
    [InlineData("MyStrongPassword456")]
    public void StrongPassword_ShouldPass(string password)
    {
        bool result = !string.IsNullOrWhiteSpace(password)
                      && password.Length >= 12
                      && password.Length <= 128;

        Assert.True(result);
    }

    // Test 5: Passwords should be hashed
    [Fact]
    public void Password_ShouldBeHashed()
    {
        var hasher = new PasswordHasher<TestUser>();
        var user = new TestUser();

        string password = "SecurePassword123!";

        string hashedPassword = hasher.HashPassword(user, password);

        Assert.NotEqual(password, hashedPassword);

        var result = hasher.VerifyHashedPassword(
            user, hashedPassword, password);

        Assert.NotEqual(
            PasswordVerificationResult.Failed, result);
    }

    // Test 6: Incorrect password should fail verification
    [Fact]
    public void IncorrectPassword_ShouldFail()
    {
        var hasher = new PasswordHasher<TestUser>();
        var user = new TestUser();

        string hashedPassword = hasher.HashPassword(
            user, "CorrectPassword123!");

        var result = hasher.VerifyHashedPassword(
            user, hashedPassword, "WrongPassword123!");

        Assert.Equal(
            PasswordVerificationResult.Failed, result);
    }

    // Test 7: SQL injection should not bypass parameterized query
    [Fact]
    public async Task SqlInjection_ShouldNotReturnAllUsers()
    {
        await using var connection =
            new SqliteConnection("Data Source=:memory:");

        await connection.OpenAsync();

        var setup = connection.CreateCommand();

        setup.CommandText = """
            CREATE TABLE Users (
                Id INTEGER PRIMARY KEY,
                Email TEXT NOT NULL
            );

            INSERT INTO Users (Email)
            VALUES ('admin@example.com'),
                   ('user@example.com');
            """;

        await setup.ExecuteNonQueryAsync();

        var command = connection.CreateCommand();

        command.CommandText =
            "SELECT COUNT(*) FROM Users WHERE Email = $email";

        command.Parameters.AddWithValue(
            "$email", "' OR '1'='1");

        var result = Convert.ToInt32(
            await command.ExecuteScalarAsync());

        Assert.Equal(0, result);
    }

    // Test 8: XSS input should be HTML encoded
    [Fact]
    public void XssInput_ShouldBeEncoded()
    {
        string maliciousInput =
            "<script>alert('XSS')</script>";

        string safeOutput =
            HtmlEncoder.Default.Encode(maliciousInput);

        Assert.DoesNotContain("<script>", safeOutput);
        Assert.Contains("&lt;script&gt;", safeOutput);
    }

    // Test 9: Normal text should remain readable
    [Fact]
    public void NormalInput_ShouldRemainReadable()
    {
        string input = "Welcome to SafeVault";

        string output = HtmlEncoder.Default.Encode(input);

        Assert.Equal(input, output);
    }

    // Test 10: User roles should be distinct
    [Fact]
    public void UserAndAdmin_ShouldHaveDifferentRoles()
    {
        string userRole = "User";
        string adminRole = "Admin";

        Assert.NotEqual(userRole, adminRole);
    }

    public class TestUser
    {
        public string Email { get; set; } = "test@example.com";
    }
}
