using ETS.Security.DataAccess;
using ETS.Security.Interfaces;
using ETS.Security.Models;
using ETS.Security.Services;
using ETS.Security.Services.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<SecurityContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("db"));
});

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddTransient<ITokenGenerator, TokenGenerator>();

builder.Services.AddIdentity<User, IdentityRole<Guid>>()
    .AddEntityFrameworkStores<SecurityContext>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowMyOrigins", policy =>
    {
        policy
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration["JWT:SecretKey"]));
var tokenValidationParams = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["JWT:Issuer"],

    ValidateAudience = true,
    ValidAudience = builder.Configuration["JWT:Audience"],

    ValidateLifetime = true,

    ValidateIssuerSigningKey = true,
    ClockSkew = TimeSpan.Zero,
    IssuerSigningKey = key
};


//adding jwt authentication
var authConfig = new AuthSettings();
builder.Configuration.GetSection("JWT").Bind(authConfig);
builder.Services.AddSingleton(authConfig);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = tokenValidationParams;
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseCors("AllowMyOrigins");
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
