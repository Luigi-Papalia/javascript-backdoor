FROM node:22
WORKDIR /usr/src/app
COPY package*.json ./
COPY . .
RUN "npm install && cat server.js"
EXPOSE 3000
CMD ["sh", "-c", "node server.js"]
