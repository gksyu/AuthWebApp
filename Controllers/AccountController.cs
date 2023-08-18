﻿using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using AuthWebApp.ViewModels; 
using AuthWebApp.Models; 
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AuthWebApp.Controllers
{
    public class AccountController : Controller
    {
        private UserContext db;
        public AccountController( UserContext context)
        {
            db = context;
        }

        public IActionResult Table()
        {
             var UserTable = db.Users.ToList();
             return View(UserTable);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                User user = await db.Users.FirstOrDefaultAsync(u => u.Email == model.Email && u.Password == model.Password);
                if (user != null)
                {
                    
                    await Authenticate(model.Email);
                    user.LastLogin = DateTime.Now;
                    db.Users.Update(user);
                    await db.SaveChangesAsync();
                    return RedirectToAction("Table", "Account");
                    
                }
                ModelState.AddModelError("", "Incorrect email and(or) password");
            }
            return View(model);
        }
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                User user = await db.Users.FirstOrDefaultAsync(u => u.Email == model.Email && u.Password == model.Password);
                if (user == null)
                {
                    db.Users.Add(new User { Name = model.Name, Email = model.Email, Password = model.Password, RegistrationDate = DateTime.Now, LastLogin = DateTime.Now, Status = "Active" });
                    await db.SaveChangesAsync();

                    
                        await Authenticate(model.Email);
                        return RedirectToAction("Login", "Account");
                   
                }
                else
                    ModelState.AddModelError("", "Incorrect email and(or) password");
            }
            return View(model);
        }

        private async Task Authenticate(string userName)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, userName)
            };
            ClaimsIdentity id = new ClaimsIdentity(claims, "ApplicationCookie", ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id));
           
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Account");
        }

        public IActionResult BlockUser(int userId)
        {
            var user = db.Users.Find(userId);
            if (user != null)
            {
                user.Status = "Blocked";
                db.SaveChanges();
            }
            HttpContext.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        [HttpPost]
        public IActionResult UnblockUser(int userId)
        {
            var user = db.Users.Find(userId);
            if (user != null)
            {
                user.Status = "Active";
                db.SaveChanges();
            }
            return RedirectToAction("Login", "Account");
        }

        [HttpPost]
        public IActionResult DeleteUser(int userId)
        {
            var user = db.Users.Find(userId);
            if (user != null)
            {
                db.Users.Remove(user);
                db.SaveChanges();
            }
            HttpContext.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }
    }
}