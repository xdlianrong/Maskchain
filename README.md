# Maskash
## 环境配置
注意，各种库所在的目录中不能出现中文字符 / 空格等  
空格会被下面要安装的 GMP 库自动编译代码读到，让代码误以为输入已完成造成编译失败  
#### procps库
1. 安装两个库： sudo apt install libncurses5-dev libncursesw5-dev  
2. sudo apt install procps  
3. sudo apt install libprocps4-dev

#### GMP库
1. sudo apt install m4  
2. 到 https://gmplib.org/ 下载 GMP 包，Maskash 开发团队使用的是6.1.2  
3. 解压后进入 gmp 所在文件夹  
4. $./configure --enable-cxx
5. $make
6. $make check
7. $sudo make install
