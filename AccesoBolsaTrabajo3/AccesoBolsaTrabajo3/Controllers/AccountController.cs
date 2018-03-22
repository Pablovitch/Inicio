using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using AccesoBolsaTrabajo3.Models;
using System.Configuration;
using Newtonsoft.Json.Linq;
using Infobip.Api.Model.Sms.Mt.Send;
using Infobip.Api.Model.Sms.Mt.Send.Textual;
using Infobip.Api.Client;
using Infobip.Api.Config;
using Infobip.Api.Model;
using System.Collections.Generic;
using AccesoBolsaTrabajo3.Controllers;
using static AccesoBolsaTrabajo3.Controllers.ManageController;
using RestSharp;
using System.Text.RegularExpressions;

namespace AccesoBolsaTrabajo3.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;
        private DataBaseSAGAEntitiesValidation _db;
        private string puerto = ConfigurationManager.AppSettings["Puerto"];

        public AccountController()
        {
            _db = new DataBaseSAGAEntitiesValidation();
        }

        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager )
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            //var userphone = await UserManager.FindAsync(model.UserName, model.Password);
            //var username = "";

            //if (userphone.PhoneNumberConfirmed == true)
            //{
            //    username = "52" + model.UserName;
            //}
            //else { username = model.UserName; }

            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(model.UserName, model.Password);
                if (user != null)
                {
                    if (user.EmailConfirmed == true || user.PhoneNumberConfirmed == true)
                    {
                        // await SignInAsync(user, model.RememberMe); return RedirectToLocal(returnUrl);

                        var email = user.Email;
                        var idp = (from p in _db.AspNetUsers
                                   where p.Email.Equals(email)
                                   select p).ToList();
                        var CandidatoId = idp[0].IdPersona;

                        if (string.IsNullOrEmpty(Convert.ToString(CandidatoId)))
                        { // Al no existir persona se va al paso 1
                            return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + user.Id); //Redirect("http://192.168.8.107:446/DatosContacto/" + user.Id);
                        }
                        else
                        {
                            Guid FmCandIdPersona = new Guid(Convert.ToString(CandidatoId));

                            var step = (from s in _db.FormulariosIniciales
                                        where s.CandidatoId.Equals(FmCandIdPersona)
                                        select s).ToList();
                            switch (step[0].Paso)  // Productivo
                            {
                                case 0:
                                    // Paso 1
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + user.Id);
                                    break;
                                case 1:
                                    // Paso 2
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/Direccion/" + CandidatoId);
                                    break;
                                case 2:
                                    // Paso 3
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosPerfilComponent/" + CandidatoId);
                                    break;
                                default:
                                    // Paso de datos generales pre-registro listo.
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosGenerales/" + CandidatoId);
                                    break;
                            }


                            //switch (step[0].Paso)
                            //{
                            //    case 0:
                            //        // Paso 1
                            //        return Redirect("http://192.168.8.107:446/DatosContacto/" + user.Id);
                            //        break;
                            //    case 1:
                            //        // Paso 2
                            //        return Redirect("http://192.168.8.107:446/Direccion/" + CandidatoId);
                            //        break;
                            //    case 2:
                            //        return Redirect("http://192.168.8.107:446/DatosPerfilComponent/" + CandidatoId);
                            //        break;
                            //    default:
                            //        // Paso de datos generales.
                            //        return Redirect("http://192.168.8.107:446/DatosGenerales/" + CandidatoId);
                            //        break;
                            //}


                            //if (step[0].Paso1 == true)
                            //{
                            //    if (step[0].Paso2 == true)
                            //    {
                            //        if (step[0].Paso3 == true)
                            //        { // Paso de datos generales.
                            //            //await SignInAsync(user, model.RememberMe);
                            //            return Redirect("http://sagainn.com.mx:"+puerto+"/DatosGenerales/" + CandidatoId);
                            //        }
                            //        else
                            //        { // Paso 3
                            //            //await SignInAsync(user, model.RememberMe);
                            //            return Redirect("http://sagainn.com.mx:"+puerto+"/DatosPerfilComponent/" + CandidatoId);
                            //        }
                            //    }
                            //    else
                            //    {
                            //        // Paso 2
                            //        //await SignInAsync(user, model.RememberMe);
                            //        return Redirect("http://sagainn.com.mx:"+puerto+"/Direccion/" + CandidatoId);
                            //    }
                            //}
                            //else
                            //{
                            //    // Paso 1
                            //    // Agregar correo con problema de IdPersona con paso 1 activo.
                            //    //await SignInAsync(user, model.RememberMe);
                            //    return Redirect("http://sagainn.com.mx:"+puerto+"/DatosContacto/" + user.Id);
                            //}
                        }



                    }
                    else
                    {
                        ModelState.AddModelError("", "Confirma tu correo o tu numero de télefono.");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Usuario inválido.");
                }
            }
            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Requerir que el usuario haya iniciado sesión con nombre de usuario y contraseña o inicio de sesión externo
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // El código siguiente protege de los ataques por fuerza bruta a los códigos de dos factores.
            // Si un usuario introduce códigos incorrectos durante un intervalo especificado de tiempo, la cuenta del usuario
            // se bloqueará durante un período de tiempo especificado.
            // Puede configurar el bloqueo de la cuenta en IdentityConfig
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent:  model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Código no válido.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {;
            ViewBag.showSuccessAlert = false;

            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {

            //if (model.Aviso == false)
            //{
            //    ViewBag.showSuccessAlert = true;
            //    ModelState.AddModelError("", "¡Oops! Aun no has aceptado el aviso de privacidad.");
            //}

            if (string.IsNullOrWhiteSpace(model.Email) && string.IsNullOrWhiteSpace(model.PhoneNumber) || string.IsNullOrEmpty(model.Password) && string.IsNullOrEmpty(model.ConfirmPassword))
            {
                ModelState.AddModelError("", "¡Oops! Aun te queda información por capturar. Inténtalo de nuevo");
            }
            else
            {
                // Validamos estructura del password ingresado.
                var mayus = model.Password.Any(c => char.IsUpper(c));
                var min = model.Password.Any(c => char.IsLower(c));
                var num = model.Password.Any(c => char.IsDigit(c));
                var symbol = model.Password.Any(c => char.IsLetterOrDigit(c));
                if (mayus == false || min == false || num == false || symbol== false)
                {
                    ModelState.AddModelError("", "¡Oops! la contraseña no cumple con los requisitos: Necesitas una minúscula, una mayúscula y un número. Inténtalo de nuevo.");
                }



                if (ModelState.IsValid)
                {
                    //var Correo = from[""];
                    //var correo = Convert.ToInt32(model.Email);


                    if (string.IsNullOrWhiteSpace(model.Email))  // Válidación de usuario por # de telefono.
                    {

                        String NumberPhone = model.PhoneNumber.Substring(0,10);
                        String Voice = model.PhoneNumber.Substring(10);
                        String ValidaVoz = ConfigurationManager.AppSettings["ClaveVoz"];
                        Voice.ToLower();

                        var userphone = new ApplicationUser { UserName = NumberPhone, PhoneNumber = NumberPhone };
                        userphone.PhoneNumberConfirmed = true;
                        userphone.Email = userphone.PhoneNumber + "@p.com";

                        var resultphone = await UserManager.CreateAsync(userphone, model.Password);

                        if (resultphone.Succeeded)
                        {

                            // Generar el token y enviarlo

                            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(userphone.Id, NumberPhone);

                            var phone = userphone.PhoneNumber.ToString();

                            List<string> Destino = new List<string>(1) { ConfigurationManager.AppSettings["Lada"] + phone };

                            if (Voice == ValidaVoz)  // Indicador de mensaje de voz al candidato.
                            {

                                string[] result = Regex.Split(code, ""); // Separamos los numeros del codigo obtenido para enviarlos al mensaje de voz.
                                string Codigo = "";
                                for (int i = 0; i < result.Length; i++)
                                {
                                    if (i > 0 && i < 7)
                                    {
                                        Codigo = Codigo + result[i] + "    ";
                                    }
                                }

                                var client = new RestClient("https://api.infobip.com/tts/3/single");
                                var requestvoice = new RestRequest(Method.POST);
                                requestvoice.AddHeader("accept", "application/json");
                                requestvoice.AddHeader("content-type", "application/json");
                                requestvoice.AddHeader("authorization", "Basic "+ ConfigurationManager.AppSettings["InfobipToken"]);
                                requestvoice.AddParameter("application/json", "{\n  \"from\": \"523323053385\",\n  \"to\": \"" + ConfigurationManager.AppSettings["Lada"] + phone + "\",\n  \"text\": \"Tu código es:  " + Codigo + "      Tu código es:  " + Codigo + "\",\n  \"language\": \""+ConfigurationManager.AppSettings["LanguajeCode"] +"\"\"speechRate\": 0.5,\n}", ParameterType.RequestBody);
                                IRestResponse response = client.Execute(requestvoice);

                            }
                            else
                            {

                                // Msj con SMS.

                                BasicAuthConfiguration BASIC_AUTH_CONFIGURATION = new BasicAuthConfiguration(ConfigurationManager.AppSettings["BaseUrl"], ConfigurationManager.AppSettings["UserInfobip"], ConfigurationManager.AppSettings["PassInfobip"]);

                                SendSingleTextualSms smsClient = new SendSingleTextualSms(BASIC_AUTH_CONFIGURATION);

                                SMSTextualRequest request = new SMSTextualRequest
                                {
                                    From = "Damsa",
                                    To = Destino,
                                    Text = ConfigurationManager.AppSettings["NameAppMsj"] + " te envia tu código de verificacion: " + code

                                };

                                // Msj de voz.

                                SMSResponse smsResponse = await smsClient.ExecuteAsync(request); // Manda el mensaje con código.

                                SMSResponseDetails sentMessageInfo = smsResponse.Messages[0];

                            }

                            return RedirectToAction("ConfirmPhone", "Account", new { PhoneNumber = NumberPhone, idtf = userphone.Id });


                            //if (UserManager.SmsService != null)
                            //{
                            //    var message = new IdentityMessage
                            //    {
                            //        Destination = model.PhoneNumber,
                            //        Body = "Su código de seguridad es: " + code
                            //    };
                            //    await UserManager.SmsService.SendAsync(message);
                            //}

                            //return RedirectToAction("VerifyPhone", "Account");

                            //return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.PhoneNumber });
                            //return RedirectToAction("Confirm", "Account", new { Email = user.Email });
                            //return RedirectToAction("RegistrarNumero", "Account");

                        }


                    }
                    else  // Validación de usuario por e-mail.
                    {

                        var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                        user.Email = model.Email;
                        user.PhoneNumber = model.PhoneNumber;

                        //user.EmailConfirmed = true;
                        var result = await UserManager.CreateAsync(user, model.Password);

                        if (result.Succeeded)
                        {
                            System.Net.Mail.MailMessage m = new System.Net.Mail.MailMessage(
                                  new System.Net.Mail.MailAddress("inntec@damsa.com.mx", "DAMSA Registro"),
                                  new System.Net.Mail.MailAddress(user.Email));
                            m.Subject = "Confirmación  Email";

                            //m.Body = string.Format("<BR/>Gracias por su registro, por favor haga clic en el siguiente enlace para completar su registro: <a href=\"{0}\" title=\"User Email Confirm\">{0}</a>", "http://sagainn.com.mx:" + puerto + "/DatosContacto/" + user.Id);
                            m.Body = string.Format("Para {0}<BR/>Gracias por su registro, por favor haga clic en el siguiente enlace para completar su registro: <a href=\"{1}\" title=\"User Email Confirm\">{1}</a>", user.UserName, Url.Action("ConfirmEmail", "Account", new { Token = user.Id, Email = user.Email }, Request.Url.Scheme));
                            m.IsBodyHtml = true;
                            System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient(ConfigurationManager.AppSettings["SmtpDamsa"], Convert.ToInt16(ConfigurationManager.AppSettings["SMTPPort"]));
                            smtp.EnableSsl = true;
                            smtp.Credentials = new System.Net.NetworkCredential(ConfigurationManager.AppSettings["UserDamsa"], ConfigurationManager.AppSettings["PassDamsa"]);
                            smtp.Send(m);
                            return RedirectToAction("Confirm", "Account", new { Email = user.Email });
                        }
                        else
                        {
                            AddErrors(result);
                        }
                    }
                }
            }
            // If we got this far, something failed, redisplay form
            //return RedirectToAction("VerifyPhoneNumber2", "Account");
            return View(model);

            //return RedirectToAction("AddPhoneNumber", "Account");
        }


    [AllowAnonymous]
    public ActionResult Confirm(string Email)
    {
        ViewBag.Email = Email;
        return View();
    }
    // GET: /Account/ConfirmEmail
    [AllowAnonymous]
    public async Task<ActionResult> ConfirmEmail(string Token, string Email)
    {
        ApplicationUser user = this.UserManager.FindById(Token);
        if (user != null)
        {
            if (user.Email == Email)
            {
                    user.EmailConfirmed = true;
                    await UserManager.UpdateAsync(user);
                    //await SignInAsync(user, isPersistent: false);

                    //var id = user.Id;
                    //return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + id);
                    return RedirectToAction("ConfirmaEmail", "Home", new { ConfirmedEmail = user.Email });
                }
            else
            {
                return RedirectToAction("Confirm", "Account", new { Email = user.Email });
            }
        }
        else
        {
            return RedirectToAction("Confirm", "Account", new { Email = "" });
        }

    }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByNameAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // No revelar que el usuario no existe o que no está confirmado
                    return View("ForgotPasswordConfirmation");
                }

                // Para obtener más información sobre cómo habilitar la confirmación de cuenta y el restablecimiento de contraseña, visite http://go.microsoft.com/fwlink/?LinkID=320771
                // Enviar correo electrónico con este vínculo
                // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                // await UserManager.SendEmailAsync(user.Id, "Restablecer contraseña", "Para restablecer la contraseña, haga clic <a href=\"" + callbackUrl + "\">aquí</a>");
                // return RedirectToAction("ForgotPasswordConfirmation", "Account");
            }

            // Si llegamos a este punto, es que se ha producido un error y volvemos a mostrar el formulario
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await UserManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // No revelar que el usuario no existe
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            var result = await UserManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Account");
            }
            AddErrors(result);
            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Solicitar redireccionamiento al proveedor de inicio de sesión externo
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/SendCode
        [AllowAnonymous]
        public async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            var userId = await SignInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View("Error");
            }
            var userFactors = await UserManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/SendCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SendCode(SendCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            // Generar el token y enviarlo
            if (!await SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider))
            {
                return View("Error");
            }
            return RedirectToAction("VerifyCode", new { Provider = model.SelectedProvider, ReturnUrl = model.ReturnUrl, RememberMe = model.RememberMe });
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Si el usuario ya tiene un inicio de sesión, iniciar sesión del usuario con este proveedor de inicio de sesión externo
            var result = await SignInManager.ExternalSignInAsync(loginInfo, isPersistent: false);
            switch (result)
            {
                case SignInStatus.Success:

                    var user = new ApplicationUser { UserName = loginInfo.Email, Email = loginInfo.Email };

                    var idp = (from p in _db.AspNetUsers
                               where p.Email.Equals(user.Email)
                               select p).ToList();
                    var CandidatoId = idp[0].IdPersona;
                    var id = idp[0].Id;

                    if (string.IsNullOrEmpty(Convert.ToString(CandidatoId)))
                    { // Al no existir persona se va al paso 1
                        return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + id); //Redirect("http://192.168.8.107:446/DatosContacto/" + user.Id);
                    }
                    else
                    {
                        Guid FmCandIdPersona = new Guid(Convert.ToString(CandidatoId));

                        var step = (from s in _db.FormulariosIniciales
                                    where s.CandidatoId.Equals(FmCandIdPersona)
                                    select s).ToList();
                        switch (step[0].Paso)  // Productivo
                        {
                            case 0:
                                // Paso 1
                                return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + id);
                                break;
                            case 1:
                                // Paso 2
                                return Redirect("http://sagainn.com.mx:" + puerto + "/Direccion/" + CandidatoId);
                                break;
                            case 2:
                                // Paso 3
                                return Redirect("http://sagainn.com.mx:" + puerto + "/DatosPerfilComponent/" + CandidatoId);
                                break;
                            default:
                                // Paso de datos generales pre-registro listo.
                                return Redirect("http://sagainn.com.mx:" + puerto + "/DatosGenerales/" + CandidatoId);
                                break;
                        }
                    }

                    //return RedirectToLocal(returnUrl);

                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.RequiresVerification:
                    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = false });
                case SignInStatus.Failure:
                default:
                    // Si el usuario no tiene ninguna cuenta, solicitar que cree una.
                    var user1 = new ApplicationUser { UserName = loginInfo.Email, Email = loginInfo.Email };
                    var result1 = await UserManager.CreateAsync(user1);
                    if (result1.Succeeded)
                    {
                        result1 = await UserManager.AddLoginAsync(user1.Id, loginInfo.Login);
                        //await SignInManager.SignInAsync(user1, isPersistent: false, rememberBrowser: false);

                        var idp1 = (from p in _db.AspNetUsers
                                    where p.Email.Equals(user1.Email)
                                    select p).ToList();
                        var CandidatoId1 = idp1[0].IdPersona;
                        var id1 = idp1[0].Id;

                        if (string.IsNullOrEmpty(Convert.ToString(CandidatoId1)))
                        { // Al no existir persona se va al paso 1
                            return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + id1); //Redirect("http://192.168.8.107:446/DatosContacto/" + user.Id);
                        }
                        else
                        {
                            Guid FmCandIdPersona = new Guid(Convert.ToString(CandidatoId1));

                            var step = (from s in _db.FormulariosIniciales
                                        where s.CandidatoId.Equals(FmCandIdPersona)
                                        select s).ToList();

                            switch (step[0].Paso)  // Productivo
                            {
                                case 0:
                                    // Paso 1
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + id1);
                                    break;
                                case 1:
                                    // Paso 2
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/Direccion/" + CandidatoId1);
                                    break;
                                case 2:
                                    // Paso 3
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosPerfilComponent/" + CandidatoId1);
                                    break;
                                default:
                                    // Paso de datos generales pre-registro listo.
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosGenerales/" + CandidatoId1);
                                    break;
                            }
                        }



                        ViewBag.ReturnUrl = returnUrl;
                        ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                        return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email = loginInfo.Email });
                    }
                    else
                    {
                        return View("ErrorLoginRedSocial");
                    }

            }
        }


        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult PreguntasFrecuentes()
        {
            return View();
        }



       // GET: /Account/Register
       [HttpGet]
       [AllowAnonymous]
        public ActionResult ReportarProblema()
        {
            //return View();
            return PartialView("_ReportarProblemaPartial");
        }




      //  Este método envia la informacion para Autorizar el token rdca19
       [HttpPost]
        public ActionResult ReportarProblema(string Email, string Commentary)
        {
            JObject data = new JObject();
            data["Respuesta"] = true;

            using (DataBaseSAGAEntities bd = new DataBaseSAGAEntities())
            {
                try
                {
                    var Cosulata = bd.usp_InsertarProblema(Email, Commentary);
                }
                catch
                {
                    data["Respuesta"] = false;
                }
            }
            return RedirectToAction("Index", "Home");
        }



        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Manage");
            }

            if (ModelState.IsValid)
            {
                // Obtener datos del usuario del proveedor de inicio de sesión externo
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                        var email = user.Email;

                        var idp = (from p in _db.AspNetUsers
                                   where p.Email.Equals(email)
                                   select p).ToList();
                        var CandidatoId = idp[0].IdPersona;

                        if (string.IsNullOrEmpty(Convert.ToString(CandidatoId)))
                        { // Al no existir persona se va al paso 1
                            return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + user.Id);
                        }else
                        {
                            Guid FmCandIdPersona = new Guid(Convert.ToString(CandidatoId));

                            var step = (from s in _db.FormulariosIniciales
                                        where s.CandidatoId.Equals(FmCandIdPersona)
                                        select s).ToList();

                            switch (step[0].Paso)  // Productivo
                            {
                                case 0:
                                    // Paso 1
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + user.Id);
                                    break;
                                case 1:
                                    // Paso 2
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/Direccion/" + CandidatoId);
                                    break;
                                case 2:
                                    // Paso 3
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosPerfilComponent/" + CandidatoId);
                                    break;

                                case 3:
                                    // Paso 3
                                    return RedirectToLocal(returnUrl);
                                    break;

                                default:
                                    // Paso de datos generales pre-registro listo.
                                    return Redirect("http://sagainn.com.mx:" + puerto + "/DatosGenerales/" + CandidatoId);
                                    break;
                            }

                        }

                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        //
        // GET: /Manage/ConfirmPhone
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmPhone(string phoneNumber, string idtf)
        {
            ViewBag.PhoneNumber = phoneNumber;
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(idtf, phoneNumber);
            return phoneNumber == null ? View("Error") : View(new ConfirmPhoneNumberViewModel { PhoneNumber = phoneNumber });
            //return View();
        }

        //
        // POST: /Manage/VerifyPhoneNumber
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmPhone(ConfirmPhoneNumberViewModel model)
        {
            //if (!ModelState.IsValid)
            //{
            //    return View(model);
            //}

            var idp = (from p in _db.AspNetUsers
                       where p.PhoneNumber.Equals(model.PhoneNumber)
                       select p).ToList();
            var cid = idp[0].Id;

            var result = await UserManager.ChangePhoneNumberAsync(cid, model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(cid);
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return Redirect("http://sagainn.com.mx:" + puerto + "/DatosContacto/" + cid);
                //return Redirect("http://localhost:59984/DatosContacto/" + cid);

            }
            // Si llegamos a este punto, es que se ha producido un error, volvemos a mostrar el formulario
            ModelState.AddModelError("", "¡Oops! tú código no es correcto, Intentalo de nuevo.");
            return View(model);
        }


        #region Aplicaciones auxiliares
        // Se usa para la protección XSRF al agregar inicios de sesión externos
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        public object WebSecurity { get; private set; }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }


        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}