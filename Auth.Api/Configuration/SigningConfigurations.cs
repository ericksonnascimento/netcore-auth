using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Configuration
{
    public class SigningConfigurations
    {
        private const string keyString = "76C67AD9C01A4F07B25FE045FF6651D5BC25AC8417D34CD5B47FCD01DFBA30A654E2A479EE0040469C8EF82C3C69E85183C70032A26D4A94869AA70D6A8A684CCBA62F43309549EF87731B8EB7EF8DC0D77C60CA97F34DA6A44EEEEB33AEAABBD55AC43E5A564B3FA6BC89AA36F43D2909F3BB489BBE448CB57B097FE070EDA";
        public SecurityKey Key { get; }
        public SigningCredentials SigningCredentials { get; }

        public SigningConfigurations()
        {

            var symmetricKeyBytes = Encoding.ASCII.GetBytes(keyString);
            var symmetricKey = new SymmetricSecurityKey(symmetricKeyBytes);

            SigningCredentials = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256);

            Key = SigningCredentials.Key;
           
        }
    }
}