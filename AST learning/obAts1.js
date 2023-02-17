const fs = require("fs");
const esprima = require('esprima'); //ECMAScript(JavaScript) 解析架构，主要用于多用途分析。
const estraverse = require('estraverse'); //语法树遍历辅助库（提供了两个静态方法，estraverse.traverse 和 estraverse.replace。前者单纯遍历 AST 的节点，通过返回值控制是否继续遍历到叶子节点；而 replace 方法则可以在遍历的过程中直接修改 AST，实现代码重构功能。）
const escodegen = require('escodegen');//AST的 ECMAScript （也称为JavaScript）代码生成器
const iconv = require("iconv-lite");
const de = require("./de1"); //this is encrypt function
var show = console.log;
var transToCode = escodegen.generate;

function isInArray(arr,value){// judge if the value is in array.
    for(var i = 0; i < arr.length; i++){
        if(value === arr[i]){
            return true;
        }
    }
    return false;
}

function isFixLength(node, number){
/*
    node : suspicious function call object confusion of node.
    number : int type, the key length in key-value pair in function call confusion is usually fixed.number is the key length.
*/
    let isFixnumber = true;
    let Reg = new RegExp('^[a-zA-Z]+$');// the key in object only can has character, instead of other signs.
    for(var i = 0; i < node.init.properties.length; i++){
        
        if(node.init.properties[i].key.value.length != number
            || !Reg.test(node.init.properties[i].key.value)){
            isFixnumber = false;
            break;
        }
    }
    return isFixnumber;
}

//读取加密混淆的执行函数Js 
var content = fs.readFileSync('D:\\output_RPA\\AST learning\\en1.js',{encoding:'binary'}); 
var buf = new Buffer.from(content,'binary');
var code = iconv.decode(buf,'utf-8');

//将混淆后的执行函数Js转换为AST
var ast = esprima.parse(code);

//字符串解密
ast = estraverse.replace(ast, {
    enter: function (node) {
        if (node.type == 'CallExpression' &&  //标注1
            node.callee.type == 'Identifier' && //标注2
            node.callee.name == "_0x1235" &&  //解密函数名
            node.arguments.length == 2 && 
            node.arguments[0].type == 'Literal' && //标注3
            node.arguments[1].type == 'Literal')  //标注4
        {
            let val = de._0x1235(node.arguments[0].value,node.arguments[1].value);  //标注5
            return {    
                type: esprima.Syntax.Literal,
                value: val,
                raw: val
            }
        }
    }
});


while (true)
{
    // recording connection of the input of function and name of parameters by objective type.
    var specialVar = ['_0x712ac0']; // some variable of function call of confusing is hard to find a way to deal by AST.I have to pick them in that list manually.
    var nameOfvar = [];
    var dict = {};
    ast = estraverse.replace(ast, {
        enter : function(node, parent){
            if (node.type == 'VariableDeclarator'
            && node.init != null 
            //&& !isInArray(specialVar, node.id.name) 
            && node.init.type == 'ObjectExpression'
            && node.init.properties.length > 0
            && node.init.properties[0].key.type == 'Literal'
            && isFixLength(node, 5))
            {   
                // Finding all first level objective and recording it.
                isFirstObj = true;
                for (var i = 0; i < node.init.properties.length; i++){
                    // Traversing all properties of node to check whether node is a first level objective.
                    if (node.init.properties[i].value.type == 'MemberExpression'
                        || node.init.properties[i].value.type == 'FunctionExpression'//the content of object must be funtion type.
                        && node.init.properties[i].value.body.body[0].type == 'ReturnStatement'//the inside of funtion only can have one expression which is return.
                        && node.init.properties[i].value.body.body[0].argument.type == 'CallExpression'// the return of function must be function call.
                        && node.init.properties[i].value.body.body[0].argument.callee.type == 'MemberExpression')// it will not a first level objective,  
                    {
                        isFirstObj = false;
                    }

                }

                if (isFirstObj)
                {   
                    nameOfvar.push(node.id.name);
                    //console.log('the name of variable: ', node.id.name)
                    for (var i = 0; i < node.init.properties.length; i++){

                        // recording the objective which used to confuse by the type of dictionary 
                        dict[node.init.properties[i].key.value] = node.init.properties[i].value;
                    }
                }        
            }
        }
    })

    show('The list of function call confusion to be processed :',nameOfvar);
    if (nameOfvar.length == 0)
    {
        break;
    }
    else
    {
        // replacing all nodes which involve in list named nameOfvar. 
        for(var i = 0; i < nameOfvar.length; i++)
        {   
            //console.log(nameOfvar[i] == '$0QQQ$', typeof(nameOfvar[i]))
            let name = nameOfvar[i];
            ast = estraverse.replace(ast, {
                enter : function(node){
                    if (node.type == 'MemberExpression'
                    && node.object.type == 'Identifier'
                    && node.object.name == name 
                    && dict[node.property.value] != undefined)//the elements in first level object is not function.
                    {   
                        // you can return format of AST directly when value of dict is string.
                        let key = node.property.value;
                        let val = dict[key];

                        if (val.type == 'Literal')
                        {
                            return {type: esprima.Syntax.Literal,
                                value: val.value,
                                raw: val.value};
                        }
                        else
                        {
                            //console.log('this is not literal type: ', val, transToCode(node));
                        }                       
                    }
                    else if(node.type == 'CallExpression'
                    && node.callee.type == 'MemberExpression'
                    && node.callee.object.type == 'Identifier'
                    && node.callee.object.name == name
                    //&& isInArray(dict, node.callee.property.value)//the string in menberExpression which is not in function call object but belonging to function own preperty.
                    )
                    {   
                        var key = node.callee.property.value;
                        var func = dict[key];// preparing the function in AST format first
                        
                        //show('=========', func, key, node, transToCode(node));
                        if (func.body.body[0].argument.type == 'BinaryExpression'
                            || func.body.body[0].argument.type == 'LogicalExpression')
                        {   
                            // As to binaryExpression, the parameters and return value all only have two and they 
                            // have strong relationship
                                                       
                            leftParamter = node.arguments[0];
                            rightparameter = node.arguments[1];
                            
                            if (typeof(leftParamter) == 'undefined' || typeof(rightparameter) == 'undefined')
                            {
                                console.log('this node has a type error: ', node, transToCode(node));
                            }

                            argument1 = {
                                type : esprima.Syntax.BinaryExpression,
                                left : leftParamter,
                                operator : func.body.body[0].argument.operator,
                                right : rightparameter
                            }
            
                            //console.log(node);
                            return argument1;
                        }
                        else if (func.body.body[0].argument.type == 'CallExpression')
                        {
                            /* confirming the corresponding relationship between function's parameters and input of parameters
                               by objective.*/
                            let correspond = {};
                            for(var i = 0; i < func.params.length; i++)
                            {
                                correspond[func.params[i].name] = node.arguments[i];
                            }

                            let argument = []; 
                            for (var i = 0; i < func.body.body[0].argument.arguments.length; i++)
                            {   
                                let paramterOfnode = correspond[func.body.body[0].argument.arguments[i].name];//this is order by the return of function
                                if (paramterOfnode.type == 'Identifier' 
                                    || paramterOfnode.type == 'Literal' 
                                    || paramterOfnode.type == 'FunctionExpression'
                                    || paramterOfnode.type == 'ArrayExpression'
                                    || paramterOfnode.type == 'MemberExpression'
                                    || paramterOfnode.type == 'AssignmentExpression'
                                    || paramterOfnode.type == 'CallExpression'
                                    || paramterOfnode.type == 'LogicalExpression'
                                    || paramterOfnode.type == 'ThisExpression'
                                    || paramterOfnode.type == 'ObjectExpression'
                                    || paramterOfnode.type == 'NewExpression'
                                    || paramterOfnode.type == 'UpdateExpression'
                                    || paramterOfnode.type == 'UnaryExpression')
                                {
                                    argument.push(paramterOfnode);
                                }
                                else
                                {
                                    show('this paramter is not Identifier type: ', paramterOfnode, transToCode(paramterOfnode));
                                    break;
                                }
                            }

                            //show('the argument is :', name, correspond[func.body.body[0].argument.callee.name], argument);
                            return {
                                type : esprima.Syntax.CallExpression,
                                callee : {type : esprima.Syntax.Identifier,
                                        name : correspond[func.body.body[0].argument.callee.name].name},
                                arguments : argument,
                                optional : false
                            }
                           
                        }
                    }
                    
                }
            });

            //Delete the node in list named nameOfvar that has been replaced
            ast = estraverse.replace(ast, {
                enter: function (node, parent) {
                    if (node.type == 'VariableDeclaration'
                    && node.declarations[0].type == 'VariableDeclarator'
                    && node.declarations[0].id.name == name
                    && node.declarations[0].init.type == 'ObjectExpression')
                    {   
                        if (parent.type == 'SwitchCase')
                        {
                            parent.consequent.splice(parent.consequent.indexOf(node), 1);
                        }
                        else
                        {   
                            parent.body.splice(parent.body.indexOf(node), 1);// delete by index. 
                        }                       
                    }
            }
            });

        }
    }   
}

// 平坦流处理
ast = estraverse.replace(ast, {
    enter: function (node, parent) {
        if (node.type == 'BlockStatement'
        && node.body.length > 1
        && node.body[0].type == 'VariableDeclaration'
        && node.body[0].declarations[0].init != null
        && node.body[0].declarations[0].init.type == 'CallExpression'
        && node.body[1].type == 'WhileStatement'
        )  
        {   
            
            let orderList = eval(transToCode(node.body[0].declarations[0].init));
            let originOrder = [];

            for(var i = 0; i < orderList.length; i++)
            {
                index = parseInt(orderList[i]);

                if (node.body[1].body.body[0].type == 'SwitchStatement')
                {
                    originOrder.push(node.body[1].body.body[0].cases[index].consequent[0]);
                }
            }

            return {type : esprima.Syntax.BlockStatement,
                    body: originOrder};
        }
    }
});


//处理if('xx'==='xx')
ast = estraverse.replace(ast, {
    enter: function (node,parent) {
        if (node.type == 'IfStatement' 
        && node.test.type == 'BinaryExpression'
        && node.test.left.type == 'Literal'
        && node.test.right.type == 'Literal')
        {
            if(node.test.left.value == node.test.right.value) { //if('aaa'=='aaa'){}
                switch (node.test.operator) {
                    case '!==' :  //if('aaa'!=='aaa'){}
                        for (var idx = 0; idx < node.alternate.body.length; idx++) {
                            // substitute by index
                            parent.body.splice(parent.body.indexOf(node), 0, node.alternate.body[idx]);
                        }

                        // delete by index
                        parent.body.splice(parent.body.indexOf(node), 1);
                        break
 
                    case '===' : //if('aaa'==='aaa'){}
                        for (var idx = 0; idx < node.consequent.body.length; idx++) {
                            parent.body.splice(parent.body.indexOf(node), 0, node.consequent.body[idx]);
                        }
                        parent.body.splice(parent.body.indexOf(node), 1);
                        break
 
                }
            } else {  //if('aaa'=='bbb'){}
                switch (node.test.operator) {
                    case '!==' : //if('aaa'!=='bbb'){}, the result is True, run consequent node
                        for (var idx = 0; idx < node.consequent.body.length; idx++) {
                            parent.body.splice(parent.body.indexOf(node), 0, node.consequent.body[idx]);
                        }
                        parent.body.splice(parent.body.indexOf(node), 1);
                        break
 
                    case '===' : //if('aaa'==='bbb'){}, the result is False, run alternate node
                        for (var idx = 0; idx < node.alternate.body.length; idx++) {
                            parent.body.splice(parent.body.indexOf(node), 0, node.alternate.body[idx]);
                        }
                        parent.body.splice(parent.body.indexOf(node), 1);
                        break
                }
            }
        }
    }
});


code = escodegen.generate(ast);  //将AST转换为JS
fs.writeFileSync('D:\\output_RPA\\AST learning\\ast1.js', code);