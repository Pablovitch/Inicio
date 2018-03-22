using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(AccesoBolsaTrabajo3.Startup))]
namespace AccesoBolsaTrabajo3
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
