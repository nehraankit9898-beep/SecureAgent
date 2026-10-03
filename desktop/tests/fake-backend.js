const http=require('node:http')
const port=Number(process.env.SECURE_AGENT_PORT)
const token=process.env.SECURE_AGENT_API_TOKEN
const server=http.createServer((request,response)=>{
 response.setHeader('Content-Type','application/json')
 if(request.url==='/health')return response.end(JSON.stringify({status:'ok',version:'2.0.0',backend:'ok',database:'ok'}))
 if(request.url==='/api/v1/settings'){if(request.headers.authorization!==`Bearer ${token}`){response.statusCode=401;return response.end(JSON.stringify({error:{code:'AUTHENTICATION_REQUIRED',message:'Authentication required'}}))}return response.end(JSON.stringify({active_provider:'LOCAL CORE'}))}
 response.statusCode=404;response.end(JSON.stringify({error:{code:'NOT_FOUND',message:'Not found'}}))
})
server.listen(port,'127.0.0.1')
process.on('SIGTERM',()=>server.close(()=>process.exit(0)))
