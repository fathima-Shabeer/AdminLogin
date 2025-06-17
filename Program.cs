using AdminLogin.Models;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// 1. Bind the AdminCredentials section from appsettings.json to the AdminCredentials class
builder.Services.Configure<AdminCredentials>(builder.Configuration.GetSection("AdminCredentials"));

// 2. Add services to the container.
builder.Services.AddControllersWithViews();

// 3. Configure Cookie Authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login"; // The path to the login page
        options.AccessDeniedPath = "/Account/AccessDenied"; // The path for access denied
        options.ExpireTimeSpan = TimeSpan.FromMinutes(20); // Cookie expiration time
        options.SlidingExpiration = true;
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// 4. Add the Authentication and Authorization middleware
// IMPORTANT: These must come after UseRouting and before MapControllerRoute
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();