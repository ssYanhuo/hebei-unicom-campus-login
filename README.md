# hebei-unicom-campus-login
河北联通 wo 的校园宽带登陆脚本，理论上适用于任意省内使用闪讯拨号的校园宽带；河北科技大学测试通过

## feature
 - 支持 Linux 拨号上网
 - 无需下载闪讯客户端
 - 可与另一台已 pppoe 闪讯拨号的设备同时在线，实现类似多拨的效果

## 如何使用
1. clone 本仓库;
2. 使用 ``` pip install ``` 补全未安装的模块
3. 执行指令:
```bash
python campus.py [账号] [密码]
```
账号密码是 wo 的校园 app 登录手机号与密码，不是 pppoe 账号密码，这里需要注意下。

## License
```
Copyright 2020 web1n

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
