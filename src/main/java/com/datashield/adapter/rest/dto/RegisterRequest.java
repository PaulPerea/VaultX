package com.datashield.adapter.rest.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Petición para registrar un usuario en ambos escenarios */
@Data
public class RegisterRequest {

    @NotBlank(message = "El nombre es requerido")
    @Size(min = 2, max = 100)
    private String name;

    @NotBlank
    @Email(message = "Email inválido")
    private String email;

    @NotBlank
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    private String password;

    @NotBlank
    @Pattern(regexp = "\\d{13,19}", message = "PAN debe tener entre 13 y 19 dígitos")
    private String pan;

    @Pattern(regexp = "\\d{9}", message = "Teléfono debe tener 9 dígitos")
    private String phone;
}
