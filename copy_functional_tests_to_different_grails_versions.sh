#!/usr/bin/env bash

GRAILS_VERSIONS="grails_3_2_8_gorm_6_1_1 grails_3_2_8_gorm_6_0_9 grails_3_1_6 grails_3_0_17"
TEMPLATE_FOLDER="./functional-test-app"
TEMPLATE_FILES="/grails-app/conf/application.groovy"
S2_QUICKSTART_FILES="/grails-app/domain/com/testapp/TestRole.groovy /grails-app/domain/com/testapp/TestUser.groovy /grails-app/domain/com/testapp/TestUserTestRole.groovy /grails-app/domain/com/testapp/TestRequestmap.groovy src/main/groovy/com/testapp/TestUserPasswordEncoderListener.groovy"

rm -rf $TEMPLATE_FOLDER/build
rm -rf $TEMPLATE_FOLDER/.gradle

cd $TEMPLATE_FOLDER
./gradlew deleteArtefacts
./gradlew copyArtefacts
cd ..

for grailsVersion in $GRAILS_VERSIONS; do
   rm -rf $TEMPLATE_FOLDER/$grailsVersion/build
   rm -rf $TEMPLATE_FOLDER/$grailsVersion/.gradle
  
   if [ -f "$TEMPLATE_FOLDER/$grailsVersion/grailsw" ];
   then 
      for file in $S2_QUICKSTART_FILES; do
          if [ -f "$TEMPLATE_FOLDER/$grailsVersion$file" ];
          then 
          rm $TEMPLATE_FOLDER/$grailsVersion$file
          fi
      done
      cd $TEMPLATE_FOLDER/$grailsVersion
      ./grailsw s2-quickstart com.testapp TestUser TestRole TestRequestmap --salt
      cd ../..
   fi
   for file in $TEMPLATE_FILES; do
       cp $TEMPLATE_FOLDER$file $TEMPLATE_FOLDER/$grailsVersion$file
   done
done

