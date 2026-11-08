
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

builder.Services.AddAuthorization();
builder.Services.AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var connectionString = "Data Source=safevault.db";

await using (var connection = new SqliteConnection(connectionString))
{
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
        CREATE TABLE IF NOT EXISTS Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Email TEXT NOT NULL UNIQUE,
            PasswordHash TEXT NOT NULL,
            Role TEXT NOT NULL
        );
        """;

    await command.ExecuteNonQueryAsync();
}

app.MapPost("/register", async (
    RegisterRequest request,
    IPasswordHasher<AppUser> hasher) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) ||
        !Regex.IsMatch(request.Email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
        return Results.BadRequest("Invalid email address.");

    if (string.IsNullOrWhiteSpace(request.Password) ||
        request.Password.Length < 12)
        return Results.BadRequest("Password must contain at least 12 characters.");

    var user = new AppUser
    {
        Email = request.Email.Trim().ToLowerInvariant(),
        Role = "User"
    };

    user.PasswordHash = hasher.HashPassword(user, request.Password);

    try
    {
        await using var db = new SqliteConnection(connectionString);
        await db.OpenAsync();

        var cmd = db.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Users (Email, PasswordHash, Role)
            VALUES ($email, $hash, $role);
            """;

        cmd.Parameters.AddWithValue("$email", user.Email);
        cmd.Parameters.AddWithValue("$hash", user.PasswordHash);
        cmd.Parameters.AddWithValue("$role", user.Role);

        await cmd.ExecuteNonQueryAsync();

        return Results.Ok("Registration successful.");
    }
    catch (SqliteException)
    {
        return Results.BadRequest("Registration could not be completed.");
    }
});

app.MapPost("/login", async (
    LoginRequest request,
    IPasswordHasher<AppUser> hasher,
    HttpContext context) =>
{
    await using var db = new SqliteConnection(connectionString);
    await db.OpenAsync();

    var cmd = db.CreateCommand();
    cmd.CommandText = """
        SELECT Id, Email, PasswordHash, Role
        FROM Users
        WHERE Email = $email;
        """;

    cmd.Parameters.AddWithValue(
        "$email",
        request.Email?.Trim().ToLowerInvariant() ?? "");

    await using var reader = await cmd.ExecuteReaderAsync();

    if (!await reader.ReadAsync())
        return Results.Unauthorized();

    var user = new AppUser
    {
        Id = reader.GetInt32(0),
        Email = reader.GetString(1),
        PasswordHash = reader.GetString(2),
        Role = reader.GetString(3)
    };

    var result = hasher.VerifyHashedPassword(
        user, user.PasswordHash, request.Password ?? "");

    if (result == PasswordVerificationResult.Failed)
        return Results.Unauthorized();

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new(ClaimTypes.Name, user.Email),
        new(ClaimTypes.Role, user.Role)
    };

    var identity = new ClaimsIdentity(
        claims, CookieAuthenticationDefaults.AuthenticationScheme);

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    return Results.Ok("Login successful.");
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(
        CookieAuthenticationDefaults.AuthenticationScheme);

    return Results.Ok("Logged out.");
}).RequireAuthorization();

app.MapGet("/profile", (HttpContext context) =>
{
    return Results.Ok(new
    {
        Email = context.User.Identity?.Name,
        Role = context.User.FindFirst(ClaimTypes.Role)?.Value
    });
}).RequireAuthorization();

app.MapGet("/admin", () =>
{
    return Results.Ok("Welcome, administrator.");
}).RequireAuthorization(policy =>
    policy.RequireRole("Admin"));

app.MapGet("/safe-output", (string input) =>
{
    return Results.Ok(new
    {
        SafeContent = HtmlEncoder.Default.Encode(input)
    });
});

app.Run();

public class AppUser
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string Role { get; set; } = "User";
}

public record RegisterRequest(string Email, string Password);
public record LoginRequest(string? Email, string? Password);
