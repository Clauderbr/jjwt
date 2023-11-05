package br.com.projetoRest.services;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.xml.bind.DatatypeConverter;

import com.google.gson.Gson;

import br.com.projetoRest.model.Credencial;
import br.com.projetoRest.model.NivelPermissao;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Path("/login")
public class LoginService {
	//Frase segredo do token, Não passar pra niguem!
	private final static String FRASE_SEGREDO =  "coloqueAquiFraseSegredoDoToken";

	//Metodo POST que valida as crendencias enviadas na request 
	//e se for validas retorna o token para o cliente	
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response fazerLogin(String crendenciaisJson){
		try {
			//Instancia o objeto Gson que vai ser responsavel de transformar o corpo da request que está na variavel crendenciaisJson
			//em um objeto java Crendencial
			Gson gson = new Gson();
			//aqui o objeto gson transforma a crendenciaisJson pra a variavel crendencial do tipo Crencendial
			Credencial crendencial = gson.fromJson(crendenciaisJson, Credencial.class);
			//Verifica se a crendencial é valida, se não for vai dar exception 
			validarCrendenciais(crendencial);
			//Se a crendencial gera o token e passa a quanidade de dias que o token vai ser valido no caso 1 dia
			String token = gerarToken(crendencial.getLogin(),10);
			//Retorna um reponse com o status 200 OK com o token gerado
			return Response.ok(token).build();
		} catch (Exception e) {
			e.printStackTrace();
			//Caso ocorra algum erro retorna uma resposta com o status 401 UNAUTHORIZED
			return Response.status(Status.UNAUTHORIZED).build();
		}
	}

	private void validarCrendenciais(Credencial crendencial) throws Exception {
		try {
			if(!crendencial.getLogin().equals("teste") || !crendencial.getSenha().equals("123"))
				throw new Exception("Crendencias n�o s�o v�lidas!");

		} catch (Exception e) {
			throw e;
		}

	}
	private  String gerarToken(String login,Integer expiraEmDias ){
		//Defini qual vai ser o algotirmo da assinatura no caso vai ser o HMAC SHA512
		SignatureAlgorithm algoritimoAssinatura = SignatureAlgorithm.HS512;
		//Data atual que data que o token foi gerado
		Date agora = new Date();
		//Define até que data o token é pelo quantidade de dias que foi passo pelo parametro expiraEmDias
		Calendar expira = Calendar.getInstance();
		expira.add(Calendar.DAY_OF_MONTH, expiraEmDias);
		//Encoda a frase sergredo pra base64 pra ser usada na geração do token 
		byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(FRASE_SEGREDO);
		SecretKeySpec key = new SecretKeySpec(apiKeySecretBytes, algoritimoAssinatura.getJcaName());
        // Criar um conjunto de reivindica��es
        Map<String, Object> claims = new HashMap<>();
        claims.put("usuarioId", login);
        claims.put("nome", "Clauder Araujo Lima");
        claims.put("iat", agora);
        claims.put("expiration", expira.getTime());
        claims.put("iss","Minha Casa & Cia LTDA");
		JwtBuilder construtor = Jwts.builder()
//				.setIssuedAt(agora) //Data que o token foi gerado
//				.setIssuer(login) //Coloca o login do usuario mais podia qualquer outra informação
				.signWith(algoritimoAssinatura, key) //coloca o algoritimo de assinatura e frase segredo ja encodada
//				.setExpiration(expira.getTime()) // coloca até que data que o token é valido
				.setClaims(claims);
		
		return construtor.compact(); //Constroi o token retorando a string dele
		
	}   
	
	public  Claims validaToken(String token) {
		try{
			//JJWT vai validar o token caso o token não seja valido ele vai executar uma exeption
			//o JJWT usa a frase segredo pra descodificar o token e ficando assim possivel
			//recuperar as informações que colocamos no payload
			 Claims claims = Jwts.parser()         
					.setSigningKey(DatatypeConverter.parseBase64Binary(FRASE_SEGREDO))
					.parseClaimsJws(token).getBody();
			 //Aqui é um exemplo que se o token for valido e descodificado 
			 //vai imprimir o login que foi colocamos no token
			 System.out.println(claims.getIssuer());
			 return claims;
		}catch(Exception ex){
			throw ex;
		}
	}

	//Metodo simples como n�o usamos banco de dados e foco é o parte autenticação
	//o metodo retorna somente um nivel de acesso, mas em uma aplicação normal
	//aqui deve ser efetuada a verfica��o de que niveis de permiss�es do usu�rio tem e retornar eles
	public NivelPermissao buscarNivelPermissao(String login) {
		
		NivelPermissao nivelPermissao = null;
		if (login.contains("teste"))
		{
			nivelPermissao = NivelPermissao.AgenteRH;
		}
		return nivelPermissao;
	}
}
