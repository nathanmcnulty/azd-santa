// Original Unlicense. Credential stays inside managed C# until private profile bytes.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
namespace SantaPilot {
 public static class Profile {
  static void Need(bool value){if(!value)throw new InvalidDataException("Private enrollment response rejected");}
  static void Fields(JsonElement e,params string[] names){Need(e.ValueKind==JsonValueKind.Object);var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var p in e.EnumerateObject())Need(Array.IndexOf(names,p.Name)>=0&&seen.Add(p.Name));Need(seen.Count==names.Length);}
  static XmlElement Value(XmlElement dict,string key){XmlElement found=null;var seen=new HashSet<string>(StringComparer.Ordinal);var entries=new List<XmlElement>();foreach(XmlNode n in dict.ChildNodes)if(n is XmlElement e)entries.Add(e);Need(entries.Count%2==0);for(int i=0;i<entries.Count;i+=2){Need(entries[i].Name=="key"&&seen.Add(entries[i].InnerText));if(entries[i].InnerText==key)found=entries[i+1];}return found;}
  static XmlDocument Baseline(byte[] bytes,string origin){
   Need(bytes.Length<=65536&&Regex.IsMatch(origin,@"\Ahttps://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z"));
   var doc=new XmlDocument();doc.XmlResolver=null;doc.PreserveWhitespace=true;
   using(var input=new MemoryStream(bytes))using(var reader=XmlReader.Create(input,new XmlReaderSettings{DtdProcessing=DtdProcessing.Ignore,XmlResolver=null}))doc.Load(reader);
   var root=doc.SelectSingleNode("/plist/dict") as XmlElement;Need(root!=null&&Value(root,"PayloadType")?.InnerText=="Configuration");
   var contents=Value(root,"PayloadContent");Need(contents!=null&&contents.Name=="array");var payloads=contents.SelectNodes("dict");Need(payloads.Count==1);
   var payload=(XmlElement)payloads[0];Need(Value(payload,"PayloadType")?.InnerText=="com.northpolesec.santa");var mode=Value(payload,"ClientMode");Need(mode!=null&&mode.Name=="integer"&&mode.InnerText=="1");Need(Value(payload,"SyncBaseURL")==null&&Value(payload,"SyncExtraHeaders")==null);return doc;
  }
  public static void CheckBaseline(byte[] bytes,string origin){Baseline(bytes,origin);}
  public static byte[] Receive(string envelope,string context,string recipient,RSA key,byte[] baseline,string origin){
   byte[] plaintext=null;
   try{Need(envelope.Length<=4096);using(var response=JsonDocument.Parse(envelope)){
    var e=response.RootElement;Fields(e,"scope","context_sha256","recipient_sha256","configuration_id","enrollment_id","ciphertext_base64");Need(e.GetProperty("scope").GetString()=="azd-santa-pilot-enrollment-v1"&&e.GetProperty("context_sha256").GetString()==context&&e.GetProperty("recipient_sha256").GetString()==recipient);
    long c=e.GetProperty("configuration_id").GetInt64(),n=e.GetProperty("enrollment_id").GetInt64();Need(c>0&&n>0);
    string ciphertext=e.GetProperty("ciphertext_base64").GetString();var encrypted=Convert.FromBase64String(ciphertext);Need(encrypted.Length==384&&Convert.ToBase64String(encrypted)==ciphertext);
    plaintext=key.Decrypt(encrypted,RSAEncryptionPadding.OaepSHA256);Need(plaintext.Length<=318);using(var decoded=JsonDocument.Parse(plaintext)){
     var p=decoded.RootElement;Fields(p,"context_sha256","secret","configuration_id","enrollment_id");Need(p.GetProperty("context_sha256").GetString()==context&&p.GetProperty("configuration_id").GetInt64()==c&&p.GetProperty("enrollment_id").GetInt64()==n);
     string secret=p.GetProperty("secret").GetString();Need(Regex.IsMatch(secret,@"\A[A-Za-z0-9_-]{16,128}\z"));var doc=Baseline(baseline,origin);var payload=(XmlElement)Value((XmlElement)doc.SelectSingleNode("/plist/dict"),"PayloadContent").SelectSingleNode("dict");
     Action<XmlElement,string,string> add=(parent,name,value)=>{var k=doc.CreateElement("key");k.InnerText=name;parent.AppendChild(k);var v=doc.CreateElement("string");v.InnerText=value;parent.AppendChild(v);};
     add(payload,"SyncBaseURL",origin+"/public/santa/sync/");var hk=doc.CreateElement("key");hk.InnerText="SyncExtraHeaders";payload.AppendChild(hk);var headers=doc.CreateElement("dict");payload.AppendChild(headers);add(headers,"Zentral-Authorization","Bearer "+secret);
     using(var output=new MemoryStream()){using(var writer=XmlWriter.Create(output,new XmlWriterSettings{Encoding=new UTF8Encoding(false),CloseOutput=false}))doc.Save(writer);return output.ToArray();}
    }
   }}finally{if(plaintext!=null)CryptographicOperations.ZeroMemory(plaintext);}
  }
 }
}
