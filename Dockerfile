# 下面的镜`uv:0.9.24-py314`为本地镜像，其Dockerfile如下：
# FROM ubuntu
# ADD ubuntu.sources /etc/apt/sources.list.d/
# ENV TZ=Asia/Shanghai
# RUN apt update && \
#     apt install -y curl && \
#     curl -LsSf https://astral.sh/uv/install.sh | sh && \
#     ln -s /root/.local/bin/uv* /usr/local/bin/ && \
#     uv python install cpython-3.14.2-linux-x86_64-gnu
#
# 其中ubuntu.sources为镜像源文件。我使用的是清华源：
# Types: deb
# URIs: http://mirrors.tuna.tsinghua.edu.cn/ubuntu
# Suites: noble noble-updates noble-backports
# Components: main restricted universe multiverse
# Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

FROM uv:0.9.24-py314
WORKDIR /app
ADD app.tar .
RUN ["uv", "sync"]
EXPOSE 8000
VOLUME ["/app/data"]
ENTRYPOINT ["uv", "run", "-m", "src"]
