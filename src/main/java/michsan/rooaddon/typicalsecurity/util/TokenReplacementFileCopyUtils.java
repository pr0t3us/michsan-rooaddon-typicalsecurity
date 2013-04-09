package michsan.rooaddon.typicalsecurity.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Map;

import org.apache.commons.lang3.Validate;

/**
 *
 * @author '<a href="mailto:ichsan@gmail.com">Muhammad Ichsan</a>'
 *
 */
public class TokenReplacementFileCopyUtils {
	public static void replaceAndCopy(InputStream in, OutputStream out,
			Map<String, String> replacements) throws IOException {
		Validate.notNull(in, "No InputStream specified");
		Validate.notNull(out, "No OutputStream specified");

		BufferedWriter writer = null;
		BufferedReader reader = null;

		try {
			writer = new BufferedWriter(new OutputStreamWriter(out));
			reader = new BufferedReader(new InputStreamReader(in));
			String line = null;

			while ((line = reader.readLine()) != null) {
				for (String token : replacements.keySet()) {
					line = line.replace(token, replacements.get(token));
				}

				writer.write(line);
				writer.write('\n');
			}
		} finally {
			if (writer != null) {
				try {
					writer.close();
				} catch (Exception e) {
				}
			}

			if (reader != null) {
				try {
					reader.close();
				} catch (Exception e) {
				}
			}
		}
	}
}
