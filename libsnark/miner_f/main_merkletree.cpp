
#include<iostream>
#include<stdlib.h>
#include<malloc.h>
#include<vector>
#include<cmath>

using namespace std;

#define DEEP 5  //根节点为第一层

struct node     //定义二叉树节点数据结构
{
	node *parent;  
    node *left;
	node *right;
	int data;
};

class MerkleTree{

private:
	vector<node> Tree;  //存储树的向量
	int index;
	void updateTree();       //更新树  
	void findLeafIndex(int leaf);      //给定一个叶节点的值，返回其在树中的索引
	void getNodeHashList(int leaf);
	void getParentList(int leaf);
	void getPathisrightList(int leaf);

public:
	vector<int> nodeHashList;   //存储需要被哈希的节点值
	vector<int> parentList;    //父节点列表
	vector<int> pathisrightList;    //存储节点是左节点还是右节点

	void creatTree();     //从叶节点开始由下到上创建并初始化二叉树
	void addLeaf(int newLeaf);        //查找叶节点中未被更新的节点，并将其值更新为naeleaf
	void deleteLeafValue(int deleteLeaf);  //将指定位置的叶子结点恢复默认值
	
	int  getRoot();
	void getPath(int leaf);
	
	void printTree();
};

void MerkleTree::creatTree()   //从叶节点开始由下到上创建并初始化二叉树
{
	//初始化节点
	for (int i = 0; i < ((int)pow(2, DEEP) - 1); i++)  
	{
		node initNode;
		initNode = { NULL, NULL, NULL, 1 };     //节点的默认值
		Tree.push_back(initNode);
	}

	//创建树
	int nodeNum = 0;   //存储创建树的过程中已被创建过关系的节点数量
	for (int j = DEEP; j >0; j--)
	{
		int parentIndex, childIndex;
		for (int i = nodeNum; i < nodeNum + (int)pow(2, j - 1); i++)
		{
			if (i < (int)pow(2, DEEP - 1))
			{
				parentIndex = nodeNum + (int)pow(2, j - 1) + (i - nodeNum) / 2;   //父节点的索引
				Tree.at(i).parent = &Tree[parentIndex];
				//cout << Tree.at(i).data << endl;
			}
			else if (i == pow(2, DEEP) - 2)
			{
				childIndex = (i - (int)pow(2, DEEP - 1)) * 2;
				Tree.at(i).left = &Tree.at(childIndex);
				Tree.at(i).right = &Tree.at(childIndex + 1);
				Tree.at(i).data = Tree.at(childIndex).data + Tree.at(childIndex + 1).data; //父节点的data值为左右孩子节点的data相加
				//cout << Tree.at(i).data << endl;
			}
			else
			{
				parentIndex = nodeNum + (int)pow(2, j - 1) + (i - nodeNum) / 2;
				Tree.at(i).parent = &Tree.at(parentIndex);
				childIndex = (i - (int)pow(2, DEEP - 1)) * 2;         //孩子节点的索引
				Tree.at(i).left = &Tree.at(childIndex);  
				Tree.at(i).right = &Tree.at(childIndex+1);
				Tree.at(i).data = Tree.at(childIndex).data + Tree.at(childIndex + 1).data;  
			}
		}
		nodeNum = nodeNum + pow(2, j - 1);
	}
}

void MerkleTree::updateTree()   //根据被更新叶节点的索引来更新整个二叉树
{
	int nodeNum;         //计算已更新节点所在的那层以及以下各层的节点数和
	for (int j = DEEP; j >1; j--)
	{
		nodeNum = (pow(2, j)*(1 - pow(2, DEEP - j))) / (1 - 2);
		(*Tree.at(index).parent).data = (*(*Tree.at(index).parent).right).data + (*(*Tree.at(index).parent).left).data;  //更新父节点的值
		index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
	}
	cout << "update done" << endl;
}


void MerkleTree::addLeaf(int newLeaf)
{
	for (index = 0; index < pow(2.0, DEEP - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == 1)
			break;
		if (index == pow(2, DEEP - 1) - 1)   //若未找到，则置index为NULL
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	Tree.at(index).data = newLeaf;   //更新节点的值
	cout << index<< endl;
	updateTree();      //更新树
	cout << "add leaf done" << endl;
}

void MerkleTree::deleteLeafValue(int deleteLeaf)
{
	for (index = 0; index < pow(2.0, DEEP - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == deleteLeaf)
			break;
		if (index == pow(2, DEEP - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	Tree.at(index).data = 1;    //更新节点的值
	updateTree();      //更新树
}

int MerkleTree::getRoot()
{
	return Tree.back().data;
}

void MerkleTree::getNodeHashList(int leaf)
{
	for (index = 0; index < pow(2.0, DEEP - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, DEEP - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
			return;
		}
	}

	int nodeNum;
	for (int j = DEEP; j > 1; j--)
	{
		//判断index对应的叶节点是左节点还是右节点
		if (index % 2 == 0)   //左节点
		{
			nodeHashList.push_back(Tree.at(index).data);
			nodeHashList.push_back(Tree.at(index+1).data);
		}
		else    //右节点
		{
			nodeHashList.push_back(Tree.at(index-1).data);
			nodeHashList.push_back(Tree.at(index).data);
		}
		nodeNum = (pow(2, j)*(1 - pow(2, DEEP - j))) / (1 - 2);
		index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
	}
}

void MerkleTree::getParentList(int leaf)
{
	for (index = 0; index < pow(2.0, DEEP - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, DEEP - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	
	int nodeNum;
	for (int j = DEEP; j > 1; j--)
	{
		nodeNum = (pow(2, j)*(1 - pow(2, DEEP - j))) / (1 - 2);
		index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
		parentList.push_back(Tree.at(index).data);
	}
}

void MerkleTree::getPathisrightList(int leaf)
{
	for (index = 0; index < pow(2.0, DEEP - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, DEEP - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	int nodeNum;
	for (int j = DEEP; j > 1; j--)
	{
		if (index % 2 == 0)   //左节点
		{
			pathisrightList.push_back(0);
		}
		else    //右节点
		{
			pathisrightList.push_back(1);
		}
		nodeNum = (pow(2, j)*(1 - pow(2, DEEP - j))) / (1 - 2);
		index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
	}
}

void MerkleTree::getPath(int leaf)
{
	for (index = 0; index < pow(2.0, DEEP - 1); index++)  
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, DEEP - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	getNodeHashList(leaf);
	getParentList(leaf);
	getPathisrightList(leaf);
}

void MerkleTree::printTree()
{
	for (int i = 0; i < Tree.size(); i++)
	{
		cout << Tree[i].data << endl;
	}
}








int main()
{
	int root;
	MerkleTree tree;
	tree.creatTree();
    tree.printTree();
    cout << "----------------------"<<endl;
	tree.addLeaf(5);
    tree.addLeaf(4);
    tree.addLeaf(6);
    tree.addLeaf(7);
    tree.addLeaf(8);
    tree.addLeaf(9);
     tree.addLeaf(2);
    tree.addLeaf(3);
     tree.addLeaf(10);
	tree.addLeaf(11);
	//tree.deleteLeafValue(5);
    tree.printTree();
    cout << "getpath:----------------------"<<endl;
	tree.getPath(11);
	for (int i = 0; i < tree.nodeHashList.size(); i++)
	{
		cout << " , "<<tree.nodeHashList[i] ;
	}
	cout << "\n----------------------"<<endl;
	for (int i = 0; i < tree.parentList.size(); i++)
	{
		cout << " , "<<tree.parentList[i];
	}
	cout << "\n----------------------"<<endl;
	for (int i = 0; i < tree.pathisrightList.size(); i++)
	{
		cout <<" , "<< tree.pathisrightList[i];
	}
	cout << "\nend----------------------"<<endl;
	root=tree.getRoot();
	cout << root << endl;
	cout << "tree" << endl;
	tree.printTree();
	return 0;
}