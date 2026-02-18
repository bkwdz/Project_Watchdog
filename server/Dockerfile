FROM node:20-bookworm

RUN apt-get update && apt-get install -y nmap iputils-ping && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

ENV PORT=8080

EXPOSE 8080

CMD ["node", "src/server.js"]
