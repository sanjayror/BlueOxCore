using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BlueOxCore
{
    public class clsResponse
    {
        public int StatusCode { get; set; }
        public string StatusText { get; set; }
        public string TwoFactorSecret { get; set; }
        public string EncodedKey { get; set; }
        public string Base64String { get; set; }
        public string Response { get; set; }
    }
}
