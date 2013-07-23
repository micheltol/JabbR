using System;
using System.ComponentModel.Composition;
using System.IO;
using System.Threading.Tasks;
using Ninject;
using JabbR.Services;

namespace JabbR.UploadHandlers
{
    internal class LocalStorageUploadHandler : IUploadHandler
    {
        private readonly IKernel _kernel;
        private readonly IJabbrConfiguration _configuration;

        [ImportingConstructor]
        public LocalStorageUploadHandler(IKernel kernel)
        {
            _kernel = kernel;
            _configuration = _kernel.Get<IJabbrConfiguration>();
        }


        public bool IsValid(string fileName, string contentType)
        {
            return true; //currently we accept everything!!
        }

        private static void CopyStream(Stream input, Stream output)
        {
            var buffer = new byte[8*1024];
            int len;
            while ((len = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, len);
            }
        }

        public async Task<UploadResult> UploadFile(string fileName, string contentType, Stream stream)
        {
            // Randomize the filename everytime so we don't overwrite files
            string randomFile = Path.GetFileNameWithoutExtension(fileName) +
                                "_" +
                                Guid.NewGuid().ToString().Substring(0, 4) + Path.GetExtension(fileName);


            var uploadSuffix = Path.Combine("Uploads", DateTime.Now.Year.ToString("D4"),
                                            DateTime.Now.Month.ToString("D2"), DateTime.Now.Day.ToString("D2"));
            var uploadDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, uploadSuffix);

            //no need to check if exsists. CreateDirectory will do that.
            Directory.CreateDirectory(uploadDir);


            await Task.Factory.StartNew(() =>
                {
                    using (Stream file = File.OpenWrite(Path.Combine(uploadDir, randomFile)))
                    {
                        CopyStream(stream, file);
                    }

                });

            var finaluri = String.Format("{0}/{1}/{2}", _configuration.BaseUrl, uploadSuffix.Replace('\\', '/'),
                                         randomFile);


            var result = new UploadResult
                {
                    Url = finaluri,
                    Identifier = fileName
                };
            return result;

        }
    }
}
