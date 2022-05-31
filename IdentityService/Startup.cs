using IdentityService.Infrastructure.Extensions;
using IdentityService.Infrastructure.Filters;
using IdentityService.Infrastructure.Routing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityService
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddConfiguration(Configuration);
            services.AddSqlServer(Configuration);
            services.AddServices();
            services.AddCustomIdentity();
            services.AddCustomAuthentication();
            services.AddVersioning();
            services.AddHttpClient();
            services.AddControllers(options => options.Conventions.Add(new RouteTokenTransformerConvention(new SlugifyParameterTransformer())));
            services.AddSwagger();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger(options => options.PreSerializeFilters.Add(SwaggerPreSerializeFilter.Filter));
                app.UseSwaggerUI(options =>
                {
                    options.RoutePrefix = "swagger";
                    options.SwaggerEndpoint("v1/swagger.json", "IdentityService API v1");
                });
            }

            // Use this if CORS is needed
            //app.UseCors(c => c.AllowAnyMethod()
            //                  .AllowAnyHeader()
            //                  .SetIsOriginAllowed(origin => true)
            //                  .AllowCredentials());

            // Use this is HTTPS is needed
            //app.UseHttpsRedirection();

            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
