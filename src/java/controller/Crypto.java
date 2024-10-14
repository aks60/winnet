package controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(name = "Crypto", urlPatterns = {"/Crypto"})
public class Crypto extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        String action = request.getParameter("action");

        if ("secret".equals(action)) {
            try {
                String encodeMesStr = request.getParameter("message").replace(" ", "+");
                byte[] decodeMesByte = Base64.getDecoder().decode(encodeMesStr);

                //Загрузим файл
                URL url = Crypto.class.getResource("/resource/crypto.key");
                Path path = Paths.get(url.toURI());
                byte[] bytes = Files.readAllBytes(path);

                //Получим ключ
                PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = kf.generatePrivate(ks);

                //Расшифровывать
                Cipher decryptCipher = Cipher.getInstance("RSA");
                decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decryptMesBytes = decryptCipher.doFinal(decodeMesByte);
                String decryptMesStr = new String(decryptMesBytes, StandardCharsets.UTF_8); //декодированный

                //Отправить ответ
                PrintWriter out = response.getWriter();
                out.println(decryptMesStr);

            } catch (Exception e) {
                System.out.println("Ошибка: Crypto.processRequest() " + e);
            }
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
