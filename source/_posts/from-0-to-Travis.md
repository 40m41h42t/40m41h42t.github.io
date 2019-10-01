---
title: 使用 Travis CI 自动部署 Hexo 博客
date: 2019-10-01 20:28:15
tags: [blog, travis]
---

最近一直在 Manjaro 和 Windows 之间切换，现在学习都已经在 Manjaro 上进行了，但是博客还在 Windows 上。虽然迁移过来并不难，但还是太麻烦了。另外写博客还要开电脑，的确有点麻烦。作为一个懒人当然是动动手自动推送最好，我就想到了用 [Travis CI](https://travis-ci.org/) 来自动部署博客。

<!--more-->

本地先通过如下流程建立一个基本的 Hexo 博客文件夹：

``` bash
npm install hexo-cli -g
hexo init blog
cd blog
npm install
```

接下来用之前博客根目录下的 `_config.yml` 替换掉这个博客根目录下的。

接着将 `source/` 目录替换掉。

我使用了 [Molunerfinn](https://github.com/Molunerfinn) 的 [hexo-theme-melody](https://github.com/Molunerfinn/hexo-theme-melody) 主题，它用了 [data files](https://hexo.io/docs/data-files.html) 特性，因此我不必修改 clone 下来的主题文件。

这样就有一个比较纯净的博客了。实际上这个目录下是自带 `.gitignore` 的，我们在根目录下 `git init`，配置相关的 remote 和 branch 即可。

接下来在根目录下新建一个 `.travis.yml` 的文件，我们就可以开始配置 Travis 了。

参考配置：

``` yaml
# 语言环境
language: node_js
node_js: stable

# 添加缓存
cache:
  directories:
    - node_modules

# 只检测 blog-source 上的代码提交
branches:
  only:
    - blog-source

# install hexo & clone theme
before_install:
  - export TZ='Asia/Shanghai' # Set Timezone
  - npm install hexo-cli -g
  - git clone -b dev https://github.com/Molunerfinn/hexo-theme-melody themes/melody

# Start: Build Lifecycle
install:
  - npm install
  - npm install hexo-renderer-jade hexo-renderer-stylus --save # medoly 主题需要的插件
  - npm install hexo-deployer-git --save # git 部署
  - npm install hexo-generator-feed # RSS generate

# 执行清缓存，生成网页操作
script:
  - hexo clean
  - hexo generate

# 设置git提交名，邮箱；替换真实token到_config.yml文件，最后depoy部署
after_script:
  - git config user.name "Quartz"
  - git config user.email "ikav.css@gmail.com"
  # 替换同目录下的_config.yml文件中gh_token字符串为travis后台刚才配置的变量，注意此处sed命令用了双引号。单引号无效！
  - sed -i "s/gh_token/${GH_TOKEN}/g" ./_config.yml
  - hexo deploy
# End: Build LifeCycle
```

可以看到，最后部署的时候我们需要输入这样的一个敏感信息。它的生成方式也比较简单：在 [GitHub](https://github.com/settings/tokens) 生成一个新 token，然后在 [Travis](https://travis-ci.org/account/repositories) 相关设置的环境变量（Environment Variables）中设置 `GH_TOKEN`（以及其他你想要的环境变量）即可。

之后推送一下就可以发现成功啦。以后想要写博客、改博客也没有必要抱着电脑，只要能联网就可以随便写了。除此之外我把图床也放在了 GitHub 上，还真是充分利用了 GitHub 的网盘和笔记功能啊（逃

除此之外，我们从项目右侧的图标中获取链接，查看生成状态。

``` markdown
[![Build Status](https://travis-ci.org/40m41h42t/40m41h42t.github.io.svg?branch=blog-source)](https://travis-ci.org/40m41h42t/40m41h42t.github.io)
```

效果如下：

[![Build Status](https://travis-ci.org/40m41h42t/40m41h42t.github.io.svg?branch=blog-source)](https://travis-ci.org/40m41h42t/40m41h42t.github.io)

## 参考文章

[Travis CI 持续集成](https://kchen.cc/2016/11/12/hexo-instructions/)

[Hexo 遇上 Travis-CI：可能是最通俗易懂的自动发布博客图文教程](https://juejin.im/post/5a1fa30c6fb9a045263b5d2a)

[Github美化-Travis与Codecov入门](https://hjptriplebee.github.io/Travis%E4%B8%8ECodecov%E5%85%A5%E9%97%A8.html/)

[持续集成在Hexo自动化部署上的实践](https://qinyuanpei.github.io/posts/3521618732/)

[使用Travis CI自动部署Hexo博客](https://www.itfanr.cc/2017/08/09/using-travis-ci-automatic-deploy-hexo-blogs/)
