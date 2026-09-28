using Altcha.AspNetCore;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Altcha.Example.Sentinel.Pages;

[AltchaVerify(RejectOnFailure = false)]
public sealed class IndexModel : PageModel
{
    public string? Status { get; private set; }

    public ServerSignatureVerificationData? VerificationData { get; private set; }

    public void OnPost()
    {
        if (!ModelState.IsValid)
        {
            Status = "Failed: " + ModelState.Values.SelectMany(v => v.Errors).First().ErrorMessage;
            return;
        }

        Status = "Verified";
        VerificationData = HttpContext.GetAltchaResult()!.VerificationData;
    }
}
