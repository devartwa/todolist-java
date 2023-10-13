package com.github.devartwa.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.devartwa.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var servletPath = request.getServletPath();

    if (servletPath.startsWith("/tasks/")) {
      var authorization = request.getHeader("Authorization");
      var authEncoded = authorization.substring("Basic".length()).trim();

      byte[] authDecode = Base64.getDecoder().decode(authEncoded);
      var authString = new String(authDecode);
      String[] credentials = authString.split(":");

      String username = credentials[0];
      String password = credentials[1];

      var foundedUser = this.userRepository.findByUsername(username);

      if (foundedUser == null) {
        response.sendError(401, "Usuário sem permissão!");
        return;
      }

      var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), foundedUser.getPassword());

      if (!passwordVerify.verified) {
        response.sendError(401, "Usuário sem permissão!");
        return;
      }

      request.setAttribute("idUser", foundedUser.getId());
    }

    filterChain.doFilter(request, response);
  }

}
