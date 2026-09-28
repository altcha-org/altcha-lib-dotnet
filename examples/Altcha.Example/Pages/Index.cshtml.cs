using Altcha.AspNetCore;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Altcha.Example.Pages;

[AltchaVerify(RejectOnFailure = false)]
public sealed class IndexModel : PageModel
{
    public string? Status { get; private set; }

    public void OnPost()
    {
        Status = ModelState.IsValid
            ? "Verified"
            : "Failed: " + ModelState.Values.SelectMany(v => v.Errors).First().ErrorMessage;
    }
}
