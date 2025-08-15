package product.service.servicio_login.dto;

/**
 * DTO utilizado para representar errores de validación de campos individuales.
 * Usado en respuestas donde se devuelven múltiples errores de entrada.
 */
public record ValidationErrorResponse(
        String field,       // Nombre del campo con error
        String message      // Mensaje de error
) {}