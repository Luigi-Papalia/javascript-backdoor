FROM node:22
WORKDIR /usr/src/app
COPY package*.json ./
COPY . .
EXPOSE 3000
CMD ["sh", "-c", "npm install && cat server.js && node server.js"]
