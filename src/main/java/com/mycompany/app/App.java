package com.mycompany.app;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.*;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.keystore.model.CreateKeyInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsHierarchicalKeyringInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.keystore.model.KMSConfiguration;


public class App 
{
    public static void main(String[] args) {
    //Hard coded values for illustration
    String keyStoreTableName = "tblKeyStore";
    String logicalKeyStoreName = "lglKeyStore";
    String kmsKeyArn = "<key arn from step 1.1>";
    String ddbTableName = "OrderInfo";
    String branchKeyId = "<derived from keystore table>";
    String branchKeyWrappingKmsKeyArn = "<key arn from step 1.1>";
    String branchKeyDdbTableName = keyStoreTableName;

	  //run only once to setup keystore
    // keyStoreCreateTable(keyStoreTableName, logicalKeyStoreName, kmsKeyArn);
 
    
    //run only once to create branch and beacon key 
  //  keyStoreCreateKey(keyStoreTableName, logicalKeyStoreName, kmsKeyArn);

  
    //run configuration per DynamoDb table
    
    List<VirtualField> virtualField = getVirtualField();
    List<StandardBeacon> beacon = getStandardBeacon();
    List<CompoundBeacon> compoundBeacon = getCompoundBeacon();
    

   KeyStore keyStore = getKeystore(
      branchKeyDdbTableName,
      logicalKeyStoreName,
      branchKeyWrappingKmsKeyArn
    );
    
    List<BeaconVersion> beaconVersions = getBeaconVersions(
      virtualField,
      beacon,
      compoundBeacon,
      keyStore,
      branchKeyId
    );
    IKeyring keyRing = getKeyRing(branchKeyId, keyStore);
   DynamoDbClient ddb = configDDBTable(ddbTableName, keyRing, beaconVersions);

    //insert orders
    HashMap<String, AttributeValue> order1 = getOrder("ABC-1001", "1672531200", "Mary", "Major", "mary.major@example.com", "1234", "012001");
    HashMap<String, AttributeValue> order2 = getOrder("ABC-1002", "1672531400", "John", "Doe", "john.doe@example.com", "1111", "122023");
    HashMap<String, AttributeValue> order3 = getOrder("ABC-1003", "1672531500", "John", "Doe", "john.doe@example.com","4567", "082026");
    HashMap<String, AttributeValue> order4 = getOrder("ABC-1004", "1672531600", "John", "Doe", "john.doe@example.com","4567", "082026");

   insertOrder(order1, ddb, ddbTableName);
   insertOrder(order2, ddb, ddbTableName);
   insertOrder(order3, ddb, ddbTableName);
   insertOrder(order4, ddb, ddbTableName);

    
    //Searchable encryption
    runQueryEmail(ddb, ddbTableName);
    runQueryNameCard(ddb, ddbTableName);
  }
    
    private static void keyStoreCreateTable(String keyStoreTableName,
                                       String logicalKeyStoreName,
                                       String kmsKeyArn) {
    
    final KeyStore keystore = KeyStore.builder().KeyStoreConfig(
            KeyStoreConfig.builder()
                    .ddbClient(DynamoDbClient.create())
                    .ddbTableName(keyStoreTableName)
                    .logicalKeyStoreName(logicalKeyStoreName)
                    .kmsClient(KmsClient.create())
                    .kmsConfiguration(KMSConfiguration.builder()
                            .kmsKeyArn(kmsKeyArn)
                            .build())
                    .build()).build();

    
      keystore.CreateKeyStore(CreateKeyStoreInput.builder().build());
    // It may take a couple minutes for the table to reflect ACTIVE state
    }
    
    private static String keyStoreCreateKey(String keyStoreTableName,
                                         String logicalKeyStoreName,
                                         String kmsKeyArn) {
   
      final KeyStore keystore = KeyStore.builder().KeyStoreConfig(
              KeyStoreConfig.builder()
                      .ddbClient(DynamoDbClient.create())
                      .ddbTableName(keyStoreTableName)
                      .logicalKeyStoreName(logicalKeyStoreName)
                      .kmsClient(KmsClient.create())
                      .kmsConfiguration(KMSConfiguration.builder()
                          .kmsKeyArn(kmsKeyArn)
                          .build())
                      .build()).build();
    
      final String branchKeyId = keystore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();
      return branchKeyId;
  }
  
  private static DynamoDbClient configDDBTable(String ddbTableName, 
                                      IKeyring kmsKeyring, 
                                      List<BeaconVersion> beaconVersions){

    // Partition and Sort keys must be SIGN_ONLY
     
    final Map<String, CryptoAction> attributeActionsOnEncrypt = new HashMap<>();
    attributeActionsOnEncrypt.put("order_id", CryptoAction.SIGN_ONLY);
    attributeActionsOnEncrypt.put("order_time", CryptoAction.SIGN_ONLY);
    attributeActionsOnEncrypt.put("email", CryptoAction.ENCRYPT_AND_SIGN);
    attributeActionsOnEncrypt.put("firstname", CryptoAction.ENCRYPT_AND_SIGN);
    attributeActionsOnEncrypt.put("lastname", CryptoAction.ENCRYPT_AND_SIGN);
    attributeActionsOnEncrypt.put("last4creditcard", CryptoAction.ENCRYPT_AND_SIGN);
    attributeActionsOnEncrypt.put("expirydate", CryptoAction.ENCRYPT_AND_SIGN);


    final Map<String, DynamoDbTableEncryptionConfig> tableConfigs = new HashMap<>();
    final DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig
        .builder()
        .logicalTableName(ddbTableName)
        .partitionKeyName("order_id")
        .sortKeyName("order_time")
        .attributeActionsOnEncrypt(attributeActionsOnEncrypt)
        .keyring(kmsKeyring)
        .search(SearchConfig.builder()
        .writeVersion(1) // MUST be 1
        .versions(beaconVersions)
        .build()
        )
    .build();
    tableConfigs.put(ddbTableName, config);

    // Create the DynamoDb Encryption Interceptor
    DynamoDbEncryptionInterceptor encryptionInterceptor = DynamoDbEncryptionInterceptor
        .builder()
        .config(DynamoDbTablesEncryptionConfig.builder()
        .tableEncryptionConfigs(tableConfigs)
        .build())
        .build();

    // Create a new AWS SDK DynamoDb client using the DynamoDb Encryption Interceptor above
    final DynamoDbClient ddb = DynamoDbClient.builder()
            .overrideConfiguration(
                    ClientOverrideConfiguration.builder()
                            .addExecutionInterceptor(encryptionInterceptor)
                            .build())
            .build();
    return ddb;
  }
  
   private static List<VirtualField> getVirtualField(){
    
    List<VirtualPart> virtualPartList = new ArrayList<>();
    VirtualPart firstnamePart = VirtualPart.builder()
        .loc("firstname")
        .build();
    VirtualPart lastnamePart = VirtualPart.builder()
        .loc("lastname")
        .build();

    virtualPartList.add(firstnamePart);
    virtualPartList.add(lastnamePart);

    VirtualField fullnameField = VirtualField.builder()
        .name("FullName")
        .parts(virtualPartList)
        .build();

    List<VirtualField> virtualFieldList = new ArrayList<>();
    
    virtualFieldList.add(fullnameField);
    return virtualFieldList;
   }
  
  private static List<StandardBeacon> getStandardBeacon(){

    List<StandardBeacon> standardBeaconList = new ArrayList<>();
    StandardBeacon emailBeacon = StandardBeacon
      .builder()
      .name("email")
      .length(15)
      .build();
    StandardBeacon last4creditcardBeacon = StandardBeacon
      .builder()
      .name("last4creditcard")
      .length(15)
      .build();
    StandardBeacon expirydateBeacon = StandardBeacon
      .builder()
      .name("expirydate")
      .length(15)
      .build();  
      
  // Virtual field
   StandardBeacon fullnameBeacon = StandardBeacon
      .builder()
      .name("FullName")
      .length(15)
      .build();  
  // End Virtual field
     
    standardBeaconList.add(emailBeacon);
    standardBeaconList.add(fullnameBeacon);
    standardBeaconList.add(last4creditcardBeacon);
    standardBeaconList.add(expirydateBeacon);

    return standardBeaconList;
  }
  


// Define compound beacon
  private static List<CompoundBeacon> getCompoundBeacon() {
  
   List<EncryptedPart> encryptedPartList_card = new ArrayList<>(); 
    EncryptedPart last4creditcardEncryptedPart = EncryptedPart
      .builder()
      .name("last4creditcard")
      .prefix("C-")
      .build();
      
    EncryptedPart expirydateEncryptedPart = EncryptedPart
      .builder()
      .name("expirydate")
      .prefix("E-")
      .build();  
      
    encryptedPartList_card.add(last4creditcardEncryptedPart);
    encryptedPartList_card.add(expirydateEncryptedPart);

    List<CompoundBeacon> compoundBeaconList = new ArrayList<>();

    CompoundBeacon CardCompoundBeacon = CompoundBeacon
      .builder()
      .name("CardCompound")
      .split("~")
      .encrypted(encryptedPartList_card)
      .build();      

    compoundBeaconList.add(CardCompoundBeacon);
    return compoundBeaconList;
  }

// Build the beacons
private static List<BeaconVersion> getBeaconVersions(List<VirtualField> virtualFieldList, List<StandardBeacon> standardBeaconList, List<CompoundBeacon> compoundBeaconList, KeyStore keyStore, String branchKeyId){
    List<BeaconVersion> beaconVersions = new ArrayList<>();
    beaconVersions.add(
            BeaconVersion.builder()
                    .virtualFields(virtualFieldList)
                    .standardBeacons(standardBeaconList)
                    .compoundBeacons(compoundBeaconList)
                    .version(1) // MUST be 1
                    .keyStore(keyStore)
                    .keySource(BeaconKeySource.builder()
                            .single(SingleKeyStore.builder()
                                    .keyId(branchKeyId)
                                    .cacheTTL(6000)
                                    .build())
                            .build())
                    .build()
    );
    return beaconVersions;
 }
 
 private static KeyStore getKeystore(
    String branchKeyDdbTableName,
    String logicalBranchKeyDdbTableName,
    String branchKeyWrappingKmsKeyArn
  ) {
    KeyStore keyStore = KeyStore
      .builder()
      .KeyStoreConfig(
        KeyStoreConfig
          .builder()
          .kmsClient(KmsClient.create())
          .ddbClient(DynamoDbClient.create())
          .ddbTableName(branchKeyDdbTableName)
          .logicalKeyStoreName(logicalBranchKeyDdbTableName)
          .kmsConfiguration(
            KMSConfiguration
              .builder()
              .kmsKeyArn(branchKeyWrappingKmsKeyArn)
              .build()
          )
          .build()
      )
      .build();
    return keyStore;
  }
  
  //Initialize keyring
private static IKeyring getKeyRing(String branchKeyId, KeyStore keyStore){
    final MaterialProviders matProv = MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
    CreateAwsKmsHierarchicalKeyringInput keyringInput = CreateAwsKmsHierarchicalKeyringInput.builder()
            .branchKeyId(branchKeyId)
            .keyStore(keyStore)
            .ttlSeconds(60)
            .build();
    final IKeyring kmsKeyring = matProv.CreateAwsKmsHierarchicalKeyring(keyringInput);
  
    return kmsKeyring;
  }
  
    private static void insertOrder(HashMap<String, AttributeValue> order, DynamoDbClient ddb, String ddbTableName) {

    final PutItemRequest putRequest = PutItemRequest.builder()
        .tableName(ddbTableName)
        .item(order)
        .build();

    final PutItemResponse putResponse = ddb.putItem(putRequest);
    assert 200 == putResponse.sdkHttpResponse().statusCode();
  }
    private static HashMap<String, AttributeValue> getOrder(
    String orderId,
    String orderTime,
    String firstName,
    String lastName,
    String email,
    String last4creditcard,
    String expirydate
  ) 
  {
    final HashMap<String, AttributeValue> order = new HashMap<>();
    order.put("order_id", AttributeValue.builder().s(orderId).build());
    order.put("order_time", AttributeValue.builder().s(orderTime).build());
    order.put("firstname", AttributeValue.builder().s(firstName).build());
    order.put("lastname", AttributeValue.builder().s(lastName).build());
    order.put("email", AttributeValue.builder().s(email).build());
    order.put("last4creditcard", AttributeValue.builder().s(last4creditcard).build());
    order.put("expirydate", AttributeValue.builder().s(expirydate).build());

    return order;
  }
  
  private static void runQueryEmail(DynamoDbClient ddb, String ddbTableName) {
    Map<String, String> expressionAttributesNames = new HashMap<>();
    expressionAttributesNames.put("#e", "email");

    Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
    expressionAttributeValues.put(
      ":e",
      AttributeValue.builder().s("mary.major@example.com").build()
    );

    QueryRequest queryRequest = QueryRequest
      .builder()
      .tableName(ddbTableName)
      .indexName("aws_dbe_b_email-index")
      .keyConditionExpression("#e = :e")
      .expressionAttributeNames(expressionAttributesNames)
      .expressionAttributeValues(expressionAttributeValues)
      .build();

    final QueryResponse queryResponse = ddb.query(queryRequest);
    assert 200 == queryResponse.sdkHttpResponse().statusCode();

    List<Map<String, AttributeValue>> items = queryResponse.items();

    for (Map<String, AttributeValue> returnedItem : items) {
      System.out.println(returnedItem.get("order_id").s());
    }
  }
  
  private static void runQueryNameCard(DynamoDbClient ddb, String ddbTableName) {
    Map<String, String> expressionAttributesNames = new HashMap<>();
    expressionAttributesNames.put("#PKName", "FullName");
    expressionAttributesNames.put("#SKName", "CardCompound");


   Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
    expressionAttributeValues.put(
      ":PKValue",
      AttributeValue.builder().s("JohnDoe").build()
      );
    expressionAttributeValues.put(
      ":SKValue",
      AttributeValue.builder().s("C-4567~E-082026").build()
      ); 
    
    QueryRequest queryRequest = QueryRequest
      .builder()
      .tableName(ddbTableName)
      .indexName("aws_dbe_b_VirtualNameCardCompound-index")
      .keyConditionExpression("#PKName = :PKValue and #SKName = :SKValue")
      .expressionAttributeNames(expressionAttributesNames)
      .expressionAttributeValues(expressionAttributeValues)
      .build();

    final QueryResponse queryResponse = ddb.query(queryRequest);

    // Validate query was returned successfully
    assert 200 == queryResponse.sdkHttpResponse().statusCode();

    List<Map<String, AttributeValue>> items = queryResponse.items();

    for (Map<String, AttributeValue> returnedItem : items) {
      System.out.println(returnedItem.get("order_id").s());
    }
  }
 }