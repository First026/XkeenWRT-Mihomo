package main
import (
 "encoding/binary"
 "os"
 "path/filepath"
 "github.com/klauspost/compress/zstd"
 "github.com/metacubex/mihomo/component/trie"
 "github.com/metacubex/mihomo/component/cidr"
 "github.com/metacubex/mihomo/component/geodata/router"
 "google.golang.org/protobuf/proto"
)
func mrs(name string, behavior byte, count int64, encode func(*zstd.Encoder)error) {
 f,e:=os.Create(filepath.Join(os.Args[1],name)); if e!=nil{panic(e)}; defer f.Close()
 w,e:=zstd.NewWriter(f,zstd.WithWindowSize(1<<20));if e!=nil{panic(e)}
 w.Write([]byte{'M','R','S',1,behavior});binary.Write(w,binary.BigEndian,count);binary.Write(w,binary.BigEndian,int64(0));if e=encode(w);e!=nil{panic(e)};if e=w.Close();e!=nil{panic(e)}
}
func main(){
 b:=trie.DomainSetBuilder{};for _,v:=range []string{"+.example.org","exact.test","*.wild.test"}{if e:=b.Insert(v);e!=nil{panic(e)}};d:=b.Build()
 mrs("domains.mrs",0,3,func(w *zstd.Encoder)error{return d.WriteBin(w)})
 ip:=cidr.NewIpCidrSet();ip.AddIpCidrForString("192.0.2.0/24");ip.AddIpCidrForString("2001:db8::/32");ip.Merge()
 mrs("addresses.mrs",1,2,func(w *zstd.Encoder)error{return ip.WriteBin(w)})
 site,_:=proto.Marshal(&router.GeoSiteList{Entry:[]*router.GeoSite{{CountryCode:"TEST",Domain:[]*router.Domain{{Type:router.Domain_Domain,Value:"example.org"},{Type:router.Domain_Full,Value:"exact.test"}}}}})
 geo,_:=proto.Marshal(&router.GeoIPList{Entry:[]*router.GeoIP{{CountryCode:"TEST",Cidr:[]*router.CIDR{{Ip:[]byte{192,0,2,0},Prefix:24}}}}})
 if e:=os.WriteFile(filepath.Join(os.Args[1],"geosite.dat"),site,0644);e!=nil{panic(e)};if e:=os.WriteFile(filepath.Join(os.Args[1],"geoip.dat"),geo,0644);e!=nil{panic(e)}
}
