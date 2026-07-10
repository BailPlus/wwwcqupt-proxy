FROM openresty/openresty:alpine-slim-amd64

# 安装 lsqlite3（用于黑名单持久化）
RUN apk add --no-cache lua5.1-lsqlite3

# 复制项目文件
WORKDIR /app
COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY src/lua/      /app/
COPY preflight.sh  /app/

# 数据卷
VOLUME ["/data"]
ENV UNBAN_CODE_SECRET=''
EXPOSE 443

# CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
