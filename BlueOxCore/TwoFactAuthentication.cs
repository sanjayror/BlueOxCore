using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Gma.QrCodeNet.Encoding;
using Gma.QrCodeNet.Encoding.Windows.Render;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using Newtonsoft.Json;
using System.Drawing.Imaging;

namespace BlueOxCore
{
    public class TwoFactAuthentication
    {
        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        private string strMongoDBUrl, strMongoDBName, strMongoDBTableName, ApplicationName = string.Empty;

        MongoClient client = null;
        MongoServer server = null;
        MongoDatabase mongoDatabase = null;

        public TwoFactAuthentication()
        {

            //strMongoDBUrl = ConfigurationManager.AppSettings["MongoDBUrl"];
            //strMongoDBName = ConfigurationManager.AppSettings["MongoDBName"].ToString();
            //strMongoDBTableName = ConfigurationManager.AppSettings["MongoDBTableName"].ToString();
            //ApplicationName = ConfigurationManager.AppSettings["ApplicationName"].ToString();

            strMongoDBUrl = "mongodb://192.168.12.179:27017";
            strMongoDBName = "2FactAuthencation";
            strMongoDBTableName = "2FactAuthencation";
            ApplicationName = "PetroIT";

            client = new MongoClient(strMongoDBUrl);
            server = client.GetServer(); //No Need of This
            mongoDatabase = server.GetDatabase(strMongoDBName);
        }

        public clsReturn Is2FAEnable(string UserName)
        {
            clsReturn objResponseMain = new clsReturn();

            try
            {
                var _success = false;
                var colPurge = mongoDatabase.GetCollection<BsonDocument>(strMongoDBTableName);
                var Detail = mongoDatabase.GetCollection<MTwoFactAuthencation>(strMongoDBTableName).FindAll().Where(t => t.UserName.ToLower() == UserName.ToLower());

                string strSecret = Detail.Select(t => t.Secret).FirstOrDefault();
                int intStatus = Detail.Select(t => t.Status).FirstOrDefault();

                if (strSecret == null || strSecret == "")
                {
                    _success = false;
                }
                else
                {
                    _success = true;
                }

                if (_success == false)
                {
                    clsResponse objResponseGenSecret = GenerateSecret(16);
                    if (objResponseGenSecret.StatusCode != 200)
                    {
                        return objResponseMain;
                    }

                    MTwoFactAuthencation objMTwoFactAuthencation = new MTwoFactAuthencation();
                    objMTwoFactAuthencation.UserName = UserName;
                    objMTwoFactAuthencation.Secret = objResponseGenSecret.EncodedKey;

                    objResponseMain.Response = GenerateQRCode(objMTwoFactAuthencation);
                    clsResponse objResponseMongo = SaveinMongo(objMTwoFactAuthencation, objResponseGenSecret);
                    if (objResponseMongo.StatusCode != 200)
                    {
                        return objResponseMain;
                    }
                }
                else
                {
                    if (intStatus == 0)
                    {
                        MTwoFactAuthencation objMTwoFactAuthencation = new MTwoFactAuthencation();
                        objMTwoFactAuthencation.UserName = UserName;
                        objMTwoFactAuthencation.Secret = new Base32Encoder().Encode(Encoding.ASCII.GetBytes(strSecret));
                        objResponseMain.Response = GenerateQRCode(objMTwoFactAuthencation);
                    }
                }

                objResponseMain.StatusCode = 200;
            }
            catch (Exception ex)
            {
                objResponseMain.StatusCode = 404;
                objResponseMain.StatusText = ex.Message.ToString();
            }

            string strJson = JsonConvert.SerializeObject(objResponseMain);
            return objResponseMain;
        }

        public clsReturn VerifyCode(string UserName, string strAppCode)
        {
            clsReturn objResponse = new clsReturn();
            try
            {
                string strResponse = string.Empty;

                string strGeneratedCodeStatusNotZero = mongoDatabase.GetCollection<MTwoFactAuthencation>(strMongoDBTableName).FindAll().Where(t => t.UserName.ToLower() == UserName.ToLower() && t.Status != 0).Select(t => t.Secret).FirstOrDefault();
                if (strGeneratedCodeStatusNotZero == null || strGeneratedCodeStatusNotZero == "")
                {
                    string strGeneratedCodeStatusZero = mongoDatabase.GetCollection<MTwoFactAuthencation>(strMongoDBTableName).FindAll().Where(t => t.UserName.ToLower() == UserName.ToLower() && t.Status == 0).Select(t => t.Secret).FirstOrDefault();
                    if (TimeBasedOneTimePassword.IsValid(strGeneratedCodeStatusZero, strAppCode))
                    {
                        strResponse = "success";

                        var collection = mongoDatabase.GetCollection<BsonDocument>(strMongoDBTableName);
                        var query = Query<MTwoFactAuthencation>.EQ(e => e.UserName, UserName);
                        var update = Update<MTwoFactAuthencation>.Set(e => e.Status, 1);
                        collection.Update(query, update);
                    }
                    else
                    {
                        strResponse = "failed";

                        var collection = mongoDatabase.GetCollection<BsonDocument>(strMongoDBTableName);
                        var query = Query<MTwoFactAuthencation>.EQ(e => e.UserName, UserName);
                        collection.Remove(query);
                    }
                }
                else
                {
                    if (TimeBasedOneTimePassword.IsValid(strGeneratedCodeStatusNotZero, strAppCode))
                    {
                        strResponse = "success";
                    }
                    else
                    {
                        strResponse = "failed";
                    }
                }

                objResponse.StatusCode = 200;
                objResponse.Response = strResponse;
            }
            catch (Exception ex)
            {
                objResponse.StatusCode = 404;
                objResponse.StatusText = ex.Message.ToString();
            }

            string strJson = JsonConvert.SerializeObject(objResponse);
            return objResponse;
        }

        public clsReturn Renew(string UserName)
        {
            clsReturn objResponse = new clsReturn();
            try
            {
                string strGeneratedCodeStatusNotZero = mongoDatabase.GetCollection<MTwoFactAuthencation>(strMongoDBTableName).FindAll().Where(t => t.UserName.ToLower() == UserName.ToLower()).Select(t => t.Secret).FirstOrDefault();
                if (strGeneratedCodeStatusNotZero == null || strGeneratedCodeStatusNotZero == "")
                {
                    objResponse.StatusCode = 404;
                    objResponse.Response = "failed";
                    return objResponse;
                }

                var collection = mongoDatabase.GetCollection<BsonDocument>(strMongoDBTableName);
                var query = Query<MTwoFactAuthencation>.EQ(e => e.UserName, UserName);
                collection.Remove(query);

                objResponse.StatusCode = 200;
                objResponse.Response = "success";
            }
            catch (Exception ex)
            {
                objResponse.StatusCode = 404;
                objResponse.Response = "failed";
                objResponse.StatusText = ex.Message.ToString();
            }

            return objResponse;
        }

        private clsResponse SaveinMongo(MTwoFactAuthencation param, clsResponse prmResponse)
        {
            clsResponse objResponse = new clsResponse();
            try
            {
                var colPurge = mongoDatabase.GetCollection<BsonDocument>(strMongoDBTableName);
                var docPurge = new BsonDocument
                {
                     { "UserName", param.UserName }, { "Secret", prmResponse.TwoFactorSecret }, { "Status", 0 }
                };
                colPurge.Insert(docPurge);

                objResponse.StatusCode = 200;
            }
            catch (Exception ex)
            {
                objResponse.StatusCode = 404;
                objResponse.StatusText = ex.Message.ToString();
            }
            return objResponse;
        }

        private string GenerateQRCode(MTwoFactAuthencation param)
        {
            string strQRCode = string.Empty;
            string AuthenticatorUri = GenerateQrCodeUri(param.UserName, param.Secret);

            clsResponse objResponseMongo = QRCode(AuthenticatorUri);
            if (objResponseMongo.StatusCode == 200)
            {
                strQRCode = objResponseMongo.Base64String;
            }
            else
            {
                strQRCode = objResponseMongo.StatusText;
            }
            return strQRCode;
        }

        private clsResponse GenerateSecret(int length)
        {
            clsResponse objResponse = new clsResponse();
            try
            {
                byte[] buffer = new byte[9];

                using (RandomNumberGenerator rng = RNGCryptoServiceProvider.Create())
                {
                    rng.GetBytes(buffer);
                }

                // Generates a 10 character string of A-Z, a-z, 0-9
                // Don't need to worry about any = padding from the
                // Base64 encoding, since our input buffer is divisible by 3
                string TwoFactorSecret = Convert.ToBase64String(buffer).Substring(0, 10).Replace('/', '0').Replace('+', '1');
                var key = new Base32Encoder().Encode(Encoding.ASCII.GetBytes(TwoFactorSecret));

                objResponse.StatusCode = 200;
                objResponse.TwoFactorSecret = TwoFactorSecret;
                objResponse.EncodedKey = key;
            }
            catch (Exception ex)
            {
                objResponse.StatusCode = 404;
                objResponse.StatusText = ex.Message.ToString();
            }
            return objResponse;
        }

        private string GenerateQrCodeUri(string UserName, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                HttpUtility.UrlEncode(ApplicationName),
                HttpUtility.UrlEncode(UserName),
                unformattedKey);
        }

        private clsResponse QRCode(string content)
        {
            clsResponse objResponse = new clsResponse();
            try
            {
                QrEncoder enc = new QrEncoder(ErrorCorrectionLevel.H);
                var code = enc.Encode(content);

                //---------------------------------------------------------------
                GraphicsRenderer r = new GraphicsRenderer(new FixedCodeSize(5, QuietZoneModules.Zero), Brushes.Black, Brushes.White);

                using (MemoryStream ms = new MemoryStream())
                {
                    r.WriteToStream(code.Matrix, ImageFormat.Png, ms);

                    byte[] image = ms.ToArray();

                    objResponse.Base64String = string.Format(@"<img src=""data:image/png;base64,{0}"" alt=""{1}"" />", Convert.ToBase64String(image), content);
                }
                //---------------------------------------------------------------

                objResponse.StatusCode = 200;
            }
            catch (Exception ex)
            {
                objResponse.StatusCode = 404;
                objResponse.StatusText = ex.Message.ToString() + ", Inner : " + ex.InnerException.Message.ToString();
            }
            return objResponse;
        }
    }
}
