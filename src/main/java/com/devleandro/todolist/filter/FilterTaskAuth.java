package com.devleandro.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.devleandro.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component // toda a classe que eu quiser que o spring gerencie eu preciso passar esse component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                var servletPath = request.getServletPath();

                if (servletPath.startsWith("/tasks/")){
                    //filtro pega autenticacao (usuario e senha)
                    var authorization = request.getHeader("Authorization");

                    if(authorization == null || !authorization.startsWith("Basic")){
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        return;
                    }

                    var authEncoded = authorization.substring("Basic".length()).trim();

                    byte[] authDecode = Base64.getDecoder().decode(authEncoded);

                    var authString = new String(authDecode);

                    String[] credentials = authString.split(":");
                    String username = credentials[0];
                    String password = credentials[1];

                    //valida usuario

                    var user = this.userRepository.findByUsername(username);
                    if (user == null){
                        response.sendError(401);
                    }else {
                        //valida senha
                        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                        if (passwordVerify.verified){
                            request.setAttribute("idUser", user.getId());
                            filterChain.doFilter(request, response);
                        }else{
                            response.sendError(401);
                        }
                        //...
                    }
                }   else {
                    filterChain.doFilter(request, response);
                }

    }
}
