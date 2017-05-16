#!/usr/bin/env bash

GRAILS_VERSIONS="grails_3_3"
TEMPLATE_FOLDER="./functional-test-app"
TEMPLATE_FILES="/grails-app/conf/application.groovy"
S2_QUICKSTART_FILES="/grails-app/domain/com/testapp/TestRole.groovy /grails-app/domain/com/testapp/TestUser.groovy /grails-app/domain/com/testapp/TestUserTestRole.groovy /grails-app/domain/com/testapp/TestRequestmap.groovy src/main/groovy/com/testapp/TestUserPasswordEncoderListener.groovy"

rm -rf $TEMPLATE_FOLDER/build
rm -rf $TEMPLATE_FOLDER/.gradle

cd $TEMPLATE_FOLDER
./gradlew deleteArtefacts
./gradlew copyArtefacts
cd ..


curl -s http://get.sdkman.io | bash
echo sdkman_auto_answer=true > ~/.sdkman/etc/config
if [[ $TRAVIS == 'true' ]]; then
    source "/home/travis/.sdkman/bin/sdkman-init.sh"
    sdk install grails 3.3.0.M1
fi

sdk use grails 3.3.0.M1

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
      grails s2-quickstart com.testapp TestUser TestRole TestRequestmap --salt
      cd ../..
   fi
   for file in $TEMPLATE_FILES; do
       cp $TEMPLATE_FOLDER$file $TEMPLATE_FOLDER/$grailsVersion$file
   done
done

