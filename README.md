# WXEL
======

基于机器学习的Webshell检测工具（linux）

# 描述
======
WXEL是基于神经网络学习算法对文件压缩比、熵、最长字符、内容特征等进行学习评估，协助安全人员针对Webshell的监察。

# 使用

## 获取训练样本
1.需要在sample/webshell目录放入具有webshell特征的文件，在sample下其他目录下放入常规文件
2.编译
```shell
go build -o xsample sample/main.go 
````
3.获取训练样本
```shell
./xsample
```
当然也可以直接使用`xsample`（基于linux go 1.20.4编译）, 样本文件为`train.csv`

## 训练
1. 编译
```shell
go build -o xtrainer trainer/main.go
```
2.开始训练
```shell
./xtrainer
```
当然也可以直接使用`xtrainer`（基于linux go 1.20.4编译）
3.获取模型，模型文件位于当前目录下`module.json`

## 检测
1. 将模型赋予变量`ModuleContent`
2. 编译
```shell
go build -o webshell_detector detector/main.go
```
3.使用`webshell_detecotr -i <file or directory>`检测文件或目录

## 注意
1. 当前模型仍然存在误报，需进一步训练
2. 性能优化，可针对扫描对象起多个goroutine进行扫描
3. 仅学习使用

## 联系我们
邮箱：549286007@qq.com
