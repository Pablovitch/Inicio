using Resources;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Web.Security;


namespace AccesoBolsaTrabajo3.Models

{
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }
    }

    public class ExternalLoginListViewModel
    {
        public string ReturnUrl { get; set; }
    }

    public class SendCodeViewModel
    {
        public string SelectedProvider { get; set; }
        public ICollection<System.Web.Mvc.SelectListItem> Providers { get; set; }
        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }

    public class VerifyCodeViewModel
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        [Display(Name = "Código")]
        public string Code { get; set; }
        public string ReturnUrl { get; set; }

        [Display(Name = "¿Recordar este explorador?")]
        public bool RememberBrowser { get; set; }

        public bool RememberMe { get; set; }
    }

    public class ForgotViewModel
    {
        [Required]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }
    }

    public class LoginViewModel
    {
        //[Required]
        [Display(Name = "Correo electrónico")]
        //[EmailAddress]
        public string Email { get; set; }

        //[Required]
        [Display(Name = "Usuario")]
        //[EmailAddress]
        public string UserName { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Display(Name = "IdPersona")]
        public string IdPersona { get; set; }

        [Display(Name = "¿Recordar cuenta?")]
        public bool RememberMe { get; set; }
    }

    public class RegisterViewModel
    {

        //[Required]
        [EmailAddress]
        [StringLength(50, ErrorMessageResourceType = typeof(Messages), ErrorMessageResourceName = "FormatEmail"), Display(Name = "Correo electrónico")]
        public string Email { get; set; }

        [Display(Name = "PhoneNumberConfirmed")]
        public bool PhoneNumberConfirmed { get; set; }

        [Display(Name = " aviso de privacidad ")]
        //[Range(typeof(bool), "true", "true", ErrorMessage = "Debes aceptar los términos y condiciones.")]
        public bool Aviso { get; set; }

        //[Required]
        //[EmailAddress]
        //[Display(Name = "Correo electrónico")]
        //public string Email { get; set; }



        //[Required]
        //[EmailAddress]
        //[Display(Name = "Confirmar electrónico")]
        //[Compare("Email", ErrorMessage = "El electrónico y el electrónico de confirmación no coinciden.")]
        //public string ConfirmEmail { get; set; }

        //[Required]
        [StringLength(100, ErrorMessage = "¡Oops! El número de caracteres de Teléfono debe ser al menos {2}.", MinimumLength = 10)]
        [Display(Name = "Telefono")]
        [DataType(DataType.PhoneNumber)]
        public string PhoneNumber { get; set; }


        //[Required]
        [StringLength(100, ErrorMessage = "¡Oops! El número de caracteres de {0} debe ser al menos {2}.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "contraseña")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirmar contraseña")]
        [Compare("Password", ErrorMessage = "¡Oops! Parece que la contraseña no coincide. Inténtalo de nuevo.")]
        public string ConfirmPassword { get; set; }

    }

    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "El número de caracteres de {0} debe ser al menos {2}.", MinimumLength = 4)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirmar contraseña")]
        [Compare("Password", ErrorMessage = "La contraseña y la contraseña de confirmación no coinciden.")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }

    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }
    }

    public class ConfirmPhoneNumberViewModel
    {
        [Required]
        [Display(Name = "Código")]
        public string Code { get; set; }

        [Required]
        [Phone]
        [Display(Name = "Número de teléfono")]
        public string PhoneNumber { get; set; }
    }
}
