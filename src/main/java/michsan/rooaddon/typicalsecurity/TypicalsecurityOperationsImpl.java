package michsan.rooaddon.typicalsecurity;

import static org.springframework.roo.support.util.XmlUtils.findFirstElement;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

import michsan.rooaddon.typicalsecurity.util.TokenReplacementFileCopyUtils;

import org.apache.commons.lang3.Validate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.springframework.roo.classpath.TypeLocationService;
import org.springframework.roo.classpath.TypeManagementService;
import org.springframework.roo.classpath.details.ClassOrInterfaceTypeDetails;
import org.springframework.roo.classpath.details.ClassOrInterfaceTypeDetailsBuilder;
import org.springframework.roo.classpath.details.MemberFindingUtils;
import org.springframework.roo.classpath.details.annotations.AnnotationMetadataBuilder;
import org.springframework.roo.metadata.MetadataService;
import org.springframework.roo.model.JavaPackage;
import org.springframework.roo.model.JavaType;
import org.springframework.roo.process.manager.FileManager;
import org.springframework.roo.process.manager.MutableFile;
import org.springframework.roo.project.Dependency;
import org.springframework.roo.project.DependencyScope;
import org.springframework.roo.project.DependencyType;
import org.springframework.roo.project.Path;
import org.springframework.roo.project.PathResolver;
import org.springframework.roo.project.ProjectOperations;
import org.springframework.roo.shell.Shell;
import org.springframework.roo.support.util.FileUtils;
import org.springframework.roo.support.util.XmlElementBuilder;
import org.springframework.roo.support.util.XmlUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * Setup typical security
 *
 * @author '<a href="mailto:ichsan@gmail.com">Muhammad Ichsan</a>'
 *
 */
@Component // Use these Apache Felix annotations to register your commands class in the Roo container
@Service
public class TypicalsecurityOperationsImpl implements TypicalsecurityOperations {

	private static final transient Logger LOGGER = Logger.getLogger(TypicalsecurityOperations.class.getName());

    /**
     * Use ProjectOperations to install new dependencies, plugins, properties, etc into the project configuration
     */
    @Reference private ProjectOperations projectOperations;

    /**
     * Use TypeLocationService to find types which are annotated with a given annotation in the project
     */
    @Reference private TypeLocationService typeLocationService;

    /**
     * Use TypeManagementService to change types
     */
    @Reference private TypeManagementService typeManagementService;


	@Reference
	private MetadataService metadataService;

	@Reference
	private FileManager fileManager;

	@Reference
	private PathResolver pathResolver;

	@Reference
	private Shell shell;

	private static char separator = File.separatorChar;

	private List<String> finalMessages;

    /** {@inheritDoc} */
    @Override
	public boolean isCommandAvailable() {
        // Check if a project has been created
        return projectOperations.isFocusedProjectAvailable();
    }

    /** {@inheritDoc} */
    @Override
	public void annotateType(JavaType javaType) {
        // Use Roo's Assert type for null checks
        Validate.notNull(javaType, "Java type required");

        // Obtain ClassOrInterfaceTypeDetails for this java type
        ClassOrInterfaceTypeDetails existing = typeLocationService.getTypeDetails(javaType);

        // Test if the annotation already exists on the target type
        if (existing != null && MemberFindingUtils.getAnnotationOfType(existing.getAnnotations(), new JavaType(RooTypicalsecurity.class.getName())) == null) {
            ClassOrInterfaceTypeDetailsBuilder classOrInterfaceTypeDetailsBuilder = new ClassOrInterfaceTypeDetailsBuilder(existing);

            // Create JavaType instance for the add-ons trigger annotation
            JavaType rooRooTypicalsecurity = new JavaType(RooTypicalsecurity.class.getName());

            // Create Annotation metadata
            AnnotationMetadataBuilder annotationBuilder = new AnnotationMetadataBuilder(rooRooTypicalsecurity);

            // Add annotation to target type
            classOrInterfaceTypeDetailsBuilder.addAnnotation(annotationBuilder.build());

            // Save changes to disk
            typeManagementService.createOrUpdateTypeOnDisk(classOrInterfaceTypeDetailsBuilder.build());
        }
    }

    /** {@inheritDoc} */
    @Override
	public void annotateAll() {
        // Use the TypeLocationService to scan project for all types with a specific annotation
        for (JavaType type: typeLocationService.findTypesWithAnnotation(new JavaType("org.springframework.roo.addon.javabean.RooJavaBean"))) {
            annotateType(type);
        }
    }

    /** {@inheritDoc} */
    @Override
	public String setup(String entityPackage, String controllerPackage) {
    	finalMessages = new ArrayList<String>();

		injectDependencies();
		createUserRoleEntities(entityPackage);
		createControllers(entityPackage, controllerPackage);
		injectDatabaseBasedSecurity(entityPackage, controllerPackage);
		hideSomeFields(controllerPackage);

		for (String message : finalMessages) {
			LOGGER.warning(message);
		}
		return "Done";
	}

	private void injectDependencies() {
		List<Dependency> dependencies = new ArrayList<Dependency>();

		// Install the dependency on the add-on jar (
		dependencies.add(new Dependency("net.tanesha.recaptcha4j",
				"recaptcha4j", "0.0.7", DependencyType.JAR,
				DependencyScope.COMPILE));

		// Install dependencies defined in external XML file
		for (Element dependencyElement : XmlUtils.findElements(
				"/configuration/batch/dependencies/dependency",
				XmlUtils.getConfiguration(getClass()))) {
			dependencies.add(new Dependency(dependencyElement));
		}

		// Add all new dependencies to pom.xml
		projectOperations.addDependencies("", dependencies);
	}

	/**
	 * Create All the entities required for User, Role and User Role
	 *
	 * @param entityPackage
	 */
	private void createUserRoleEntities(String entityPackage) {

		// -----------------------------------------------------------------------------------
		// Create User entity
		// -----------------------------------------------------------------------------------
		shell.executeCommand("entity jpa --class " + entityPackage
				+ ".User --testAutomatically --permitReservedWords --table users");
		shell.executeCommand("field string --fieldName firstName --sizeMin 1 --notNull --column first_name");
		shell.executeCommand("field string --fieldName lastName --sizeMin 1 --notNull --column last_name");
		shell.executeCommand("field string --fieldName emailAddress --notNull --unique " +
				"--column email_address");
		shell.executeCommand("field string --fieldName password --sizeMin 1 --notNull --column password");
		shell.executeCommand("field date --fieldName activationDate --type java.util.Date --column activation_date");
		shell.executeCommand("field boolean --fieldName enabled --column enabled");
		shell.executeCommand("field boolean --fieldName locked --column locked");

		// -----------------------------------------------------------------------------------
		// Create Role entity
		// -----------------------------------------------------------------------------------
		shell.executeCommand("entity jpa --class " + entityPackage
				+ ".Role --testAutomatically --permitReservedWords --table roles");
		shell.executeCommand("field string --fieldName name --sizeMin 1 --notNull --unique --regexp ^ROLE_[A-Z]* --column name");
		shell.executeCommand("field string --fieldName description --sizeMax 200 --notNull --column description");

		// -----------------------------------------------------------------------------------
		// Create User Role Mapping
		// -----------------------------------------------------------------------------------
		shell.executeCommand("entity jpa --class " + entityPackage
				+ ".UserRole --testAutomatically --table users_roles");
		shell.executeCommand("field reference --fieldName user --type "
				+ entityPackage + ".User --notNull --joinColumnName user_id " +
						"--permitReservedWords");
		shell.executeCommand("field reference --fieldName role --type "
				+ entityPackage + ".Role --notNull --joinColumnName role_id " +
						"--permitReservedWords");

		// -----------------------------------------------------------------------------------
		// Create Finders for find user by email address and find user role by
		// user
		// -----------------------------------------------------------------------------------
		shell.executeCommand("finder add findUsersByEmailAddress --class " + entityPackage
				+ ".User");
		shell.executeCommand("finder add findUserRolesByUser --class " + entityPackage
				+ ".UserRole");

	}

	/**
	 * Create an Controller for User, Role and UserRole
	 *
	 * @param entityPackage
	 * @param controllerPackage
	 */
	private void createControllers(String entityPackage,
			String controllerPackage) {

		// -----------------------------------------------------------------------------------
		// Controller for User
		// -----------------------------------------------------------------------------------
		shell.executeCommand("web mvc scaffold "
				+ "--class " + controllerPackage + ".UserController "
				+ "--backingType " + entityPackage + ".User "
				+ "--path " + path("/", controllerPackage, "users"));

		// -----------------------------------------------------------------------------------
		// Controller for Role
		// -----------------------------------------------------------------------------------
		shell.executeCommand("web mvc scaffold "
				+ "--class " + controllerPackage + ".RoleController "
				+ "--backingType " + entityPackage + ".Role "
				+ "--path " + path("/", controllerPackage, "roles"));

		// -----------------------------------------------------------------------------------
		// Controller for User Role
		// -----------------------------------------------------------------------------------
		shell.executeCommand("web mvc scaffold "
				+ "--class " + controllerPackage + ".UserRoleController "
				+ "--backingType " + entityPackage + ".UserRole "
				+ "--path " + path("/", controllerPackage, "assignrole"));

	}


	private String path(String prefix, String packageName, String suffix) {
		JavaPackage rootPackage = projectOperations.getFocusedTopLevelPackage();
		String rootPackageName = rootPackage.getFullyQualifiedPackageName();

		String absolutePackageName = packageName.replace("~", rootPackageName);

		// Remove domain path: mysite.web.security => web.security
		String pathPrefix = absolutePackageName.replace(rootPackageName + ".", "");

		// Remove web.: web.security => security
		pathPrefix = pathPrefix.replace("web.", "");

		// Change into separator: security.subsecure => security/subsecure
		pathPrefix = pathPrefix.replace('.', separator);

		// "michsan.web.security" => "security/"
		// "" => ""

		if (!pathPrefix.isEmpty()) return prefix + (pathPrefix + '/') + suffix;

		return prefix + suffix;
	}

	/**
	 * Inject database based authentication provider in Spring Security
	 *
	 * @param entityPackage
	 */
	private void injectDatabaseBasedSecurity(String entityPackage,
			String controllerPackage) {

		// ----------------------------------------------------------------------
		// Run Security Setup Addon
		// ----------------------------------------------------------------------
		shell.executeCommand("security setup");

		// ----------------------------------------------------------------------
		// Copy JpaUserDetailService from template
		// ----------------------------------------------------------------------
		createJpaUserDetailService(entityPackage, controllerPackage);

		// ----------------------------------------------------------------------
		// Inject JPA based authentication provider into
		// applicationContext-security.xml
		// ----------------------------------------------------------------------
		injectJpabasedAuthProviderInXml(entityPackage);

		createMailSender();
		addForgotPasswordAndSignUpPage();
		addChangePasswordToFooter();
	}

	private void hideSomeFields(String controllerPackage) {
		String viewPath = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_WEBAPP,
				path("WEB-INF/views/", controllerPackage, "users/list.jspx"));

		doOnDoc(viewPath, new DocTask() {

			@Override
			public void process(Document doc) {
				findFirstElement("//*[@property = 'password']", doc).setAttribute("render", "false");
			}
		});


		viewPath = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_WEBAPP,
				path("WEB-INF/views/", controllerPackage, "users/show.jspx"));

		doOnDoc(viewPath, new DocTask() {

			@Override
			public void process(Document doc) {
				findFirstElement("//*[@field = 'password']", doc).setAttribute("render", "false");
			}
		});


		viewPath = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_WEBAPP,
				path("WEB-INF/views/", controllerPackage, "users/create.jspx"));

		doOnDoc(viewPath, new DocTask() {

			@Override
			public void process(Document doc) {
				findFirstElement("//*[@field = 'activationDate']", doc).setAttribute("render", "false");
			}
		});


		viewPath = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_WEBAPP,
				path("WEB-INF/views/", controllerPackage, "users/update.jspx"));

		doOnDoc(viewPath, new DocTask() {

			@Override
			public void process(Document doc) {
				findFirstElement("//*[@field = 'password']", doc).setAttribute("render", "false");
				findFirstElement("//*[@field = 'activationDate']", doc).setAttribute("render", "false");
			}
		});

	}

	private void doOnDoc(String file, DocTask task) {
		MutableFile mutableFile = null;
		Document doc;
		try {
			if (fileManager.exists(file)) {
				mutableFile = fileManager.updateFile(file);
				doc = XmlUtils.getDocumentBuilder().parse(
						mutableFile.getInputStream());
			} else {
				throw new IllegalStateException("Could not acquire " + file);
			}

			task.process(doc);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}

		XmlUtils.writeXml(mutableFile.getOutputStream(), doc);
	}

	private void createMailSender() {
		shell.executeCommand("email sender setup --hostServer smtp.gmail.com --protocol SMTP --username your-email@gmail.com --password your-email-password");
		// Sign Up email
		shell.executeCommand("email template setup --from your-email@gmail.com");

		final String springContext = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_RESOURCES,
				"META-INF/spring/applicationContext.xml");

		doOnDoc(springContext, new DocTask() {

			@Override
			public void process(Document webConfigDoc) {
				JavaPackage rootPackage = projectOperations.getFocusedTopLevelPackage();
				String artifactId = rootPackage.getLastElement();

				// Account Activation
				String emailContent = "Hi {{FIRST_NAME}} {{LAST_NAME}}!\n" +
						"\n" +
						"You had registered with us. To activate your account, please click on the following URL:\n" +
						"\n" +
						"	http://localhost:8080/" + artifactId + "/signup?e={{EMAIL_ADDRESS}}&k={{ACTIVATION_KEY}}\n" +
						"\n" +
						"Thanks";
				String newTemplateId = "accountActivationMailTemplate";
				newEmailTemplate(newTemplateId, "Account Activation", emailContent, webConfigDoc);

				// Account Recovery
				emailContent = "Hi {{FIRST_NAME}} {{LAST_NAME}}!\n" +
						"\n" +
						"You had requested account reset. To reset your account, please click on the following URL:\n" +
						"\n" +
						"	http://localhost:8080/" + artifactId + "/forgot/set?k={{KEY}}\n" +
						"\n" +
						"	Note: This link is valid only for 2 x 24 hours.\n" +
						"\n" +
						"Thanks";
				newTemplateId = "accountRecoveryMailTemplate";
				newEmailTemplate(newTemplateId, "Account Recovery", emailContent, webConfigDoc);

				// Remove default template
				Element templateBean = findFirstElement("//bean[@id = 'templateMessage']", webConfigDoc);
				templateBean.getParentNode().removeChild(templateBean);

				// Configure mailer to use TLS
				Element mailSenderBean = findFirstElement("//bean[@id = 'mailSender']", webConfigDoc);
				Validate.notNull(mailSenderBean, "Could not find mailSender bean in "
						+ springContext);

				addCommentBefore("You need this if you use GMail",
						findFirstElement("//property[@name = 'javaMailProperties']", webConfigDoc));

				finalMessages.add("Regarding email sending, you probably need to edit " +
						"src/main/resources/META-INF/spring/email.properties and " +
						"src/main/resources/META-INF/spring/applicationContext.xml");
			}
		});

	}

	private void newEmailTemplate(String newTemplateId, String newSubject, String emailContent,
			Document webConfigDoc) {
		Element masterTemplateMessageBean = findFirstElement("//bean[@id = 'templateMessage']", webConfigDoc);
		Element templateMessageBean = (Element) masterTemplateMessageBean.cloneNode(true);

		templateMessageBean.setAttribute("id", newTemplateId);

		templateMessageBean.appendChild(
				new XmlElementBuilder("property", webConfigDoc)
					.addAttribute("name", "subject")
					.addAttribute("value", newSubject)
					.build());

		templateMessageBean.appendChild(
				new XmlElementBuilder("property", webConfigDoc)
					.addAttribute("name", "text")
					.addChild(
							new XmlElementBuilder("value", webConfigDoc)
								.addChild(webConfigDoc.createCDATASection(emailContent))
								.build())
					.build());
		masterTemplateMessageBean.getParentNode().appendChild(templateMessageBean);
	}


	private static void addCommentBefore(String comment, Element element) {
		Document doc = element.getOwnerDocument();

		Text newLine = doc.createTextNode("\n");
		element.getParentNode().insertBefore(newLine, element);
		element.getParentNode().insertBefore(
				doc.createComment(comment), newLine);
	}

	/**
	 * Inject database based authentication provider into
	 * applicationContext-security.xml
	 *
	 * @param entityPackage
	 */
	private void injectJpabasedAuthProviderInXml(String entityPackage) {
		final String springSecurity = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_RESOURCES,
				"META-INF/spring/applicationContext-security.xml");

		doOnDoc(springSecurity, new DocTask() {

			@Override
			public void process(Document webConfigDoc) {
				Element firstInterceptUrl = findFirstElement("//intercept-url", webConfigDoc);
				Validate.notNull(firstInterceptUrl, "Could not find intercept-url in "
						+ springSecurity);

				// 1) Mark that some patterns needs authentication

				// /security/** must be ADMIN
				firstInterceptUrl.getParentNode().insertBefore(
						new XmlElementBuilder("intercept-url", webConfigDoc)
								.addAttribute("pattern", "/security/**")
								.addAttribute("access", "hasRole('ROLE_ADMIN')").build(),
						firstInterceptUrl);

				// /passwd/** must be authenticated
				firstInterceptUrl.getParentNode().insertBefore(
						new XmlElementBuilder("intercept-url", webConfigDoc)
								.addAttribute("pattern", "/passwd/**")
								.addAttribute("access", "isAuthenticated()").build(),
						firstInterceptUrl);



				// 2) Add JPA user service
				Element authenticationManager = findFirstElement("//authentication-manager", webConfigDoc);

				Element jpaUserServiceBean = new XmlElementBuilder(
						"beans:bean", webConfigDoc)
						.addAttribute("id", "jpaUserService")
						.addAttribute("class", qualifiedName(".security.JpaUserDetailService"))
						.build();

				authenticationManager.getParentNode().insertBefore(
						jpaUserServiceBean, authenticationManager);

				// 2) Add a password encoder
				String siteWideSalt = new BigInteger(130, new SecureRandom()).toString(32);

				Element passwordEncoderBean = new XmlElementBuilder(
						"beans:bean", webConfigDoc)
						.addAttribute("id", "passwordEncoder")
						.addAttribute("class", "org.springframework.security.crypto.password.StandardPasswordEncoder")
						.addChild(
								new XmlElementBuilder("beans:constructor-arg", webConfigDoc)
										.addAttribute("value", siteWideSalt).build())
						.build();

				authenticationManager.getParentNode().insertBefore(
						passwordEncoderBean, authenticationManager);

				// 3) Add a new auth provider bean
				Element databaseAuthenticationProviderBean = new XmlElementBuilder(
						"authentication-provider", webConfigDoc)
						.addAttribute("user-service-ref", "jpaUserService")
						.addChild(
								new XmlElementBuilder("password-encoder", webConfigDoc)
										.addAttribute("ref", "passwordEncoder").build())
						.build();

				authenticationManager.insertBefore(
						databaseAuthenticationProviderBean, authenticationManager.getFirstChild());
			}
		});
	}


	private String qualifiedName(String name) {
		JavaPackage topLevelPackage = projectOperations
				.getFocusedTopLevelPackage();
		return topLevelPackage.getFullyQualifiedPackageName() + name;
	}

	/**
	 * Copy JpaUserDetailService from template
	 *
	 * @param entityPackage
	 */
	private void createJpaUserDetailService(String entityPackage,
			String controllerPackage) {

		JavaPackage topLevelPackage = projectOperations.getFocusedTopLevelPackage();

		String packagePath = topLevelPackage.getFullyQualifiedPackageName()
				.replace('.', separator);

		String finalEntityPackage = entityPackage.replace("~",
				topLevelPackage.getFullyQualifiedPackageName());

		String finalControllerPackage = controllerPackage.replace("~",
				topLevelPackage.getFullyQualifiedPackageName());

		Map<String, String> replacements = new HashMap<String, String>();
		replacements.put("__TOP_LEVEL_PACKAGE__",
				topLevelPackage.getFullyQualifiedPackageName());
		replacements.put("__ENTITY_LEVEL_PACKAGE__", finalEntityPackage);
		replacements.put("__CONTROLLER_PACKAGE__", finalControllerPackage);
		replacements.put("__WEB_PREFIX__", path("", finalControllerPackage, ""));

		Map<String, String> fileAndTemplateMap = new HashMap<String, String>();

		// Controllers & forms
		for (String controllerName : Arrays.asList("ChangePasswordController",
				"ChangePasswordForm", "SignUpController", "SignUpForm",
				"ForgotPasswordController", "ForgotPasswordForm",
				"NewPasswordForm", "UserController", "NewPasswordForm", "UserController")) {

			fileAndTemplateMap.put(
					pathResolver.getFocusedIdentifier(Path.SRC_MAIN_JAVA,
							finalControllerPackage.replace('.', separator) + separator	+ controllerName + ".java"),
					controllerName + ".java-template");
		}

		// Services
		fileAndTemplateMap.put(
				pathResolver.getFocusedIdentifier(Path.SRC_MAIN_JAVA,
						packagePath	+ separator + "security" + separator + "JpaUserDetailService.java"),
				"JpaUserDetailService.java-template");

		// Utils
		fileAndTemplateMap.put(
				pathResolver.getFocusedIdentifier(Path.SRC_MAIN_JAVA,
						packagePath	+ separator + "util" + separator + "EncryptionUtil.java"),
				"EncryptionUtil.java-template");

		// Models
		fileAndTemplateMap.put(
				pathResolver.getFocusedIdentifier(Path.SRC_MAIN_JAVA,
						finalEntityPackage.replace('.', separator) + separator + "User.java"),
				"User.java-template");

		// Attributes
		fileAndTemplateMap.put(
				pathResolver.getFocusedIdentifier(Path.SRC_MAIN_JAVA,
						finalEntityPackage.replace('.', separator)	+ separator + "attribute" + separator + "CreateAttributes.java"),
				"CreateAttributes.java-template");

		// JSP templates
		String prefix = separator + "WEB-INF/views";
		replacements.put("__ENTITY_LEVEL_PACKAGE_WEB__", finalEntityPackage.replace('.', '_'));

		for (String fileName : Arrays.asList(
				"signup/form.jspx",
				"signup/thanks.jspx",
				"signup/error.jspx",
				"signup/views.xml",
				"forgot_password/form.jspx",
				"forgot_password/set_new.jspx",
				"forgot_password/thanks.jspx",
				"forgot_password/views.xml",
				"change_password/form.jspx",
				"change_password/thanks.jspx",
				"change_password/views.xml")) {
			fileAndTemplateMap.put(
					pathResolver.getFocusedIdentifier(Path.SRC_MAIN_WEBAPP,
							prefix	+ separator + fileName.replace('\'', separator)),
					fileName);
		}

		for (Entry<String, String> entry : fileAndTemplateMap.entrySet()) {
			MutableFile mutableFile = null;

			String targetFile = entry.getKey();
			String template = entry.getValue();
			try {

				if (fileManager.exists(targetFile)) {
					mutableFile = fileManager.updateFile(targetFile);
				}
				else {
					mutableFile = fileManager.createFile(targetFile);
				}

				TokenReplacementFileCopyUtils.replaceAndCopy(
						FileUtils.getInputStream(getClass(), template),
						mutableFile.getOutputStream(), replacements);

			} catch (Exception ioe) {
				throw new IllegalStateException(ioe);
			}
		}

		insertI18nMessages();
	}

	private void addChangePasswordToFooter() {
		final String jspx = pathResolver.getFocusedIdentifier(Path.SRC_MAIN_WEBAPP,
				"WEB-INF/views/footer.jspx");

		doOnDoc(jspx, new DocTask() {

			@Override
			public void process(Document document) {
				Element logout = findFirstElement("//a[@href=\"${logout}\"]", document);
				Validate.notNull(logout,
						"Could not find <a href=\"${logout}\"> in "
								+ jspx);

				// <c:if test="${pageContext['request'].userPrincipal != null}">
				Node principalContainer = logout.getParentNode().getParentNode();

				/*
					<c:out value=" | "/>
					<span>
					  <spring:url value="/passwd" var="passwd"/>
					  <a href="${passwd}">
					    <spring:message code="change_password"/>
					  </a>
					</span>
				 */
				principalContainer.appendChild(
						new XmlElementBuilder("c:out", document)
								.addAttribute("value", " | ").build());

				principalContainer.appendChild(
						new XmlElementBuilder("span", document)
								.addChild(
										new XmlElementBuilder("spring:url", document)
											.addAttribute("value", "/passwd")
											.addAttribute("var", "passwd")
											.build())
								.addChild(
										new XmlElementBuilder("a", document)
											.addAttribute("href", "${passwd}")
											.addChild(new XmlElementBuilder("spring:message", document)
														.addAttribute("code", "change_password")
														.build())
											.build())
								.build());
			}
		});
	}

	private void addForgotPasswordAndSignUpPage() {
		final String jspx = pathResolver.getFocusedIdentifier(Path.SRC_MAIN_WEBAPP,
				"WEB-INF/views/login.jspx");

		doOnDoc(jspx, new DocTask() {

			@Override
			public void process(Document doc) {
				Element form = findFirstElement("//form", doc);
				Validate.notNull(form, "Could not find form in " + jspx);

				/*
				<br />
			    <div>
			      <span>
			        <spring:url value="/forgot" var="forgot" />
			        <a href="${forgot}"> <spring:message code="forgot_password" /> </a>
			      </span>
			      <c:out value=" | " />
			      <span>
			        <spring:url value="/signup" var="sign_up" />
			        <spring:message code="not_a_user_yet" /><c:out value=" " /> <a href="${sign_up}"> <spring:message code="sign_up" /> </a>
			      </span>
			    </div>
				 */

				form.appendChild(new XmlElementBuilder("br", doc).build());

				form.appendChild(
						new XmlElementBuilder("div", doc)
							.addChild(new XmlElementBuilder("span", doc)
								.addChild(
										new XmlElementBuilder("spring:url", doc)
											.addAttribute("value", "/forgot")
											.addAttribute("var", "forgot")
											.build())
								.addChild(
										new XmlElementBuilder("a", doc)
											.addAttribute("href", "${forgot}")
											.addChild(new XmlElementBuilder("spring:message", doc)
														.addAttribute("code", "forgot_password")
														.build())
											.build())
								.build()) // end of span

							.addChild(new XmlElementBuilder("c:out", doc)
								.addAttribute("value", " | ")
								.build())


							.addChild(new XmlElementBuilder("span", doc)
								.addChild(
										new XmlElementBuilder("spring:message", doc)
											.addAttribute("code", "not_a_user_yet")
											.build())
								.addChild(
										new XmlElementBuilder("c:out", doc)
											.addAttribute("value", " ")
											.build())
								.addChild(
										new XmlElementBuilder("spring:url", doc)
											.addAttribute("value", "/signup")
											.addAttribute("var", "signup")
											.build())
								.addChild(
										new XmlElementBuilder("a", doc)
											.addAttribute("href", "${signup}")
											.addChild(new XmlElementBuilder("spring:message", doc)
														.addAttribute("code", "sign_up")
														.build())
											.build())
								.build()) // end of span
							.build());
			}
		});

	}

	private void insertI18nMessages() {
		String applicationProperties = pathResolver.getFocusedIdentifier(
				Path.SRC_MAIN_WEBAPP, "WEB-INF/i18n/messages.properties");

		if (!fileManager.exists(applicationProperties)) {
			throw new IllegalStateException("Could not acquire "
					+ applicationProperties);
		}

		try {
			MutableFile mutableApplicationProperties = fileManager
					.updateFile(applicationProperties);
			String originalData = convertStreamToString(mutableApplicationProperties
					.getInputStream());

			// Replace existing data
			originalData = originalData.replaceAll(
					"security_login_form_name=Name",
					"security_login_form_name=Email");
			originalData = originalData
					.replaceAll(
							"security_login_form_name_message=Enter your name",
							"security_login_form_name_message=Log in using your email address");

			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
					mutableApplicationProperties.getOutputStream()));

			out.write(originalData);
			out.write("\n\n");

			BufferedReader reader = new BufferedReader(new InputStreamReader(
					FileUtils.getInputStream(getClass(),
							"additional_message.properties")));

			String line;
			while ((line = reader.readLine()) != null) {
				out.write(line);
				out.write("\n");
			}

			reader.close();
			out.close();

		} catch (Exception e) {
			System.out.println("---> " + e.getMessage());
			throw new IllegalStateException(e);
		}

	}

	private String convertStreamToString(InputStream is) throws IOException {
		/*
		 * To convert the InputStream to String we use the Reader.read(char[]
		 * buffer) method. We iterate until the Reader return -1 which means
		 * there's no more data to read. We use the StringWriter class to
		 * produce the string.
		 */
		if (is != null) {
			Writer writer = new StringWriter();

			char[] buffer = new char[1024];
			try {
				Reader reader = new BufferedReader(new InputStreamReader(is,
						"UTF-8"));
				int n;
				while ((n = reader.read(buffer)) != -1) {
					writer.write(buffer, 0, n);
				}
			} finally {
				is.close();
			}
			return writer.toString();
		} else {
			return "";
		}
	}
}
