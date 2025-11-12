FROM node:18-slim
WORKDIR /app
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/juice-shop/juice-shop.git . && npm install --production
EXPOSE 3000
CMD ["npm","start"]
