﻿using JabbR.ContentProviders.Core;
using JabbR.Infrastructure;
using JabbR.Models;
using JabbR.Nancy;
using JabbR.Services;
using JabbR.UploadHandlers;
using Microsoft.AspNet.SignalR.Hubs;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Cookies;
using Nancy.Bootstrappers.Ninject;
using Nancy.SimpleAuthentication;
using Newtonsoft.Json;
using Ninject;
using Microsoft.AspNet.SignalR;

namespace JabbR
{
    public partial class Startup
    {
        private static KernelBase SetupNinject(IJabbrConfiguration configuration)
        {
            var kernel = new StandardKernel(new[] { new FactoryModule() });

            kernel.Bind<JabbrContext>()
                .To<JabbrContext>();

            kernel.Bind<IJabbrRepository>()
                .To<PersistedRepository>();

            kernel.Bind<IChatService>()
                  .To<ChatService>();

            kernel.Bind<IDataProtector>()
                  .To<JabbRDataProtection>();

            kernel.Bind<ICookieAuthenticationProvider>()
                  .To<JabbRFormsAuthenticationProvider>();

            kernel.Bind<ILogger>()
                  .To<RealtimeLogger>();

            kernel.Bind<IUserIdProvider>()
                  .To<JabbrUserIdProvider>();

            kernel.Bind<IJabbrConfiguration>()
                  .ToConstant(configuration);

            // We're doing this manually since we want the chat repository to be shared
            // between the chat service and the chat hub itself
            kernel.Bind<Chat>()
                  .ToMethod(context =>
                  {
                      var resourceProcessor = context.Kernel.Get<ContentProviderProcessor>();
                      var repository = context.Kernel.Get<IJabbrRepository>();
                      var cache = context.Kernel.Get<ICache>();
                      var logger = context.Kernel.Get<ILogger>();
                      var settings = context.Kernel.Get<ApplicationSettings>();

                      var service = new ChatService(cache, repository, settings);

                      return new Chat(resourceProcessor,
                                      service,
                                      repository,
                                      cache,
                                      logger);
                  });

            kernel.Bind<ICryptoService>()
                .To<CryptoService>();

            kernel.Bind<IResourceProcessor>()
                .ToConstant(new ResourceProcessor(kernel));

            kernel.Bind<IJavaScriptMinifier>()
                  .To<AjaxMinMinifier>()
                  .InSingletonScope();

            kernel.Bind<IMembershipService>()
                  .To<MembershipService>();

            kernel.Bind<ApplicationSettings>()
                  .ToMethod(context =>
                  {
                      return context.Kernel.Get<ISettingsManager>().Load();
                  });

            kernel.Bind<ISettingsManager>()
                  .To<SettingsManager>();

            kernel.Bind<IUserAuthenticator>()
                  .To<DefaultUserAuthenticator>();

            kernel.Bind<IAuthenticationService>()
                  .To<AuthenticationService>();

            kernel.Bind<IValidatorUserInformationService>()
                    .To<ValidatorUserInformationService>();

            kernel.Bind<IAuthenticationCallbackProvider>()
                  .To<JabbRAuthenticationCallbackProvider>();

            kernel.Bind<ICache>()
                  .To<DefaultCache>()
                  .InSingletonScope();

            kernel.Bind<IChatNotificationService>()
                  .To<ChatNotificationService>();

            kernel.Bind<IKeyProvider>()
                      .To<SettingsKeyProvider>();

            var serializer = JsonSerializer.Create(new JsonSerializerSettings()
            {
                DateFormatHandling = DateFormatHandling.IsoDateFormat
            });

            kernel.Bind<JsonSerializer>()
                  .ToConstant(serializer);

            kernel.Bind<UploadCallbackHandler>()
                  .ToSelf()
                  .InSingletonScope();

            kernel.Bind<UploadProcessor>()
                  .ToConstant(new UploadProcessor(kernel));

            kernel.Bind<ContentProviderProcessor>()
                  .ToConstant(new ContentProviderProcessor(kernel));

            kernel.Bind<IEmailTemplateContentReader>()
                  .To<RazorEmailTemplateContentReader>();

            kernel.Bind<IEmailTemplateEngine>()
                  .To<RazorEmailTemplateEngine>();

            kernel.Bind<IEmailSender>()
                  .To<SmtpClientEmailSender>();

            kernel.Bind<IEmailService>()
                  .To<EmailService>();

            return kernel;
        }
    }
}