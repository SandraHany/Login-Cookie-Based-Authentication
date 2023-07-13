using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationCookies.Pages;

public class IndexModel : PageModel
{
 
    [BindProperty]
    public LoginInput LoginInput { get; set; }

    public bool IsLoggedIn => HttpContext.Request.Cookies.ContainsKey("LoggedIn");

    public string Username => HttpContext.Request.Cookies["LoggedIn"];

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (LoginInput.Username == "intern" && LoginInput.Password == "summer 2023 july")
        {
            HttpContext.Response.Cookies.Append("LoggedIn", LoginInput.Username);
            return RedirectToPage();
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }

    public IActionResult OnGetLogout()
    {
        if (HttpContext.Request.Cookies.ContainsKey("LoggedIn"))
        {
            HttpContext.Response.Cookies.Delete("LoggedIn");
        }

        return RedirectToPage();
    }
}

public class LoginInput
{
    [Required(ErrorMessage = "Username is required.")]
    public string Username { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    public string Password { get; set; }
}