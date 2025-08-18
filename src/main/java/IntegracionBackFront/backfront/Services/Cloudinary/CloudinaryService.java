package IntegracionBackFront.backfront.Services.Cloudinary;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import io.netty.util.internal.ObjectUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

@Service
public class CloudinaryService {
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024;
    private static  final  String[] ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"};
    private  final Cloudinary cloudinary;

    public CloudinaryService(Cloudinary cloudinary) {
        this.cloudinary = cloudinary;
    }

    /**
     *
     * @param file
     * @return
     * @throws IOException
     */
    public String uploadImage(MultipartFile file) throws IOException{
        validateImage(file);

        Map<?,?>uploadResult = cloudinary.uploader().upload(file.getBytes(), ObjectUtils.asMap(
                "resource_type", "auto",
                "quality", "auto:good"
        ));

        return (String) uploadResult.get("secure_url");
    }

    /**
     *
     * @param file
     * @param folder
     * @return
     * @throws IOException
     */
    public  String uploadImage(MultipartFile file, String folder) throws  IOException{
        validateImage(file);

        String originalFileName = file.getOriginalFilename();
        String fileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
        String uniqueFileName = "img_" + UUID.randomUUID() + fileExtension;

        Map<String, Object> options = ObjectUtils.asMap(
                    "folder", folder,
                "public_id", uniqueFileName,
                "use_filename", false,  //Para ocupar el nombre de la imagen
                "unique_filename", false,
                "overwrite", false,
                "resource_type", "auto",
                "quality", "auto:good"
        );

        Map<?,?> uploadResult = cloudinary.uploader().upload(file.getBytes(),options);
        return (String) uploadResult.get("secure_url");
    }

    /**
     *
     * @param file
     */
    private void  validateImage(MultipartFile file){
        if (file.isEmpty()){
            throw new IllegalArgumentException("El archivo no puede estar vacio.");
        }

        if (file.getSize() > MAX_FILE_SIZE){
            throw new IllegalArgumentException("El archivo no puede ser mayor a 5MB");
        }

        String originalFileName = file.getOriginalFilename();
        if (originalFileName== null){
            throw new IllegalArgumentException("Nombre de archivo invalido");
        }

        String extension = originalFileName.substring(originalFileName.lastIndexOf(".")).toLowerCase();
        if (!Arrays.asList(ALLOWED_EXTENSIONS).contains(extension)){
            throw new IllegalArgumentException("Solo se permiten archivos JPG,JPEG, PNG y GIF");
        }

        if (!file.getContentType().startsWith("image/")){
            throw new IllegalArgumentException("El archivo deber ser una imagen válida.");
        }
    }
}
