#include<iostream>
#include<vector>
#include<algorithm>
#include<list>
#include<map>
#include<ctime>
#include<string>
#include<fstream>
#include<limits>

using namespace std;
class Decrypt
{
private:
	// consts and other known vars
	static int englishFrequency[27];
	const static int charOffset;
	const static int ciphertextLen;
	const static int numChars;
	
	// get info related vars
	int keyLen;
	char ciphertextChar[101];
	string ciphertext;
	string dictionary1;

	// section and freq related vars
	string* sections;
	int charFreq[27];
	int charProb[27];

	// decrypting related vars
	string key;
	string plaintext;

	// timing vars
	clock_t start;
	double duration;

public:
	// Functions to decrypt
	void decryptor();
	void getInfo();
	void splitCiphertext();
	void polyalphabeticAnalysis( int );
	void guessPlaintext();

	// Generalized distance function
	int distance( string, string );
};

// Settings static vars

// Cipher text length was guaranteed 100
const int Decrypt::ciphertextLen = 100;

// Characters ' ','a','b', ... ,'z'. 27 in total
const int Decrypt::numChars = 27;

// First char is ASCII 96, so the total offset is 96
const int Decrypt::charOffset = 96;

// Space is slightly more frequently seen than 'e' according to wikipedia.
//frequency of 12% is assumed since e has around 11% in ur system
//								  space, a, b, c, d, e,  f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
int Decrypt::englishFrequency[27]={12, 7, 2, 3, 3, 11, 2, 2, 5, 6, 0, 1, 3, 2, 6, 7, 2, 0, 5, 5, 8, 3, 1, 2, 0, 2, 0};

void Decrypt::decryptor()
{
	getInfo();
	start = clock();
	splitCiphertext();
	guessPlaintext();
	duration = (clock() - start) / (double)CLOCKS_PER_SEC;
	cout << "Duration: " << duration << endl;
}

void Decrypt::getInfo()
{
	// Get key length
	cout << "Key length:" << endl;
	cin >> keyLen;

	// Flush buffer
	cin.clear();
	cin.ignore( numeric_limits<streamsize>::max(), '\n');

	// Get ciphertext
	cout << "Ciphertext:" << endl;
	cin.getline( ciphertextChar, 101 );
	ciphertext = string(ciphertextChar);

	// Get dictionary
	string dictionaryEntry;
	ifstream ifs("Dictionary1.txt");
	while( getline(ifs,dictionaryEntry) )
	{
		dictionary1 += dictionaryEntry;
	}
	ifs.close();

	// Replace all spaces with the character before 'a' for simpler calculations
	replace( ciphertext.begin(), ciphertext.end(), ' ', '`' );
	replace( dictionary1.begin(), dictionary1.end(), ' ', '`' );
}

// Splits cipher text into different sections to detect polyalphabetic substitutions
void Decrypt::splitCiphertext()
{
	cout << "Splitting ciphertext" << endl;
	// Putting characters into array of strings in accordance with the key length
	// This will help detect which letter was shifted by which amount
	sections = new string[ keyLen ];
	for( int i=0; i<ciphertextLen; i++ )
	{
		sections[ i % keyLen ] += ciphertext[i];
	}

	// Test characters for each section
	// These would line up with the key at different points
	for( int i=0; i<keyLen; i++ )
	{
		polyalphabeticAnalysis( i );
	}
}


// At each offset of the key length, check what the most probable character would be
void Decrypt::polyalphabeticAnalysis( int keyOffset )
{
	cout << "Running polyalphabetic analysis" << endl;
	// Gets frequency of each letter in ciphertext per key length offset
	int charFreq[numChars];
	memset( charFreq, 0, sizeof(charFreq) );
	for( int i=0; i<(int)sections[keyOffset].size(); i++ )
	{
		charFreq[ (int)sections[keyOffset][i] - charOffset ]++;
	}

	// Calculates probability of each character based on freq of letters in English
	int charProb[numChars];
	memset( charProb, 0, sizeof(charProb) );
	for( int i=0; i<numChars; i++ )
	{
		int placeHolder = i;
		for( int j=0; j<numChars; j++ )
		{
			charProb[i] += englishFrequency[j] * charFreq[placeHolder % numChars];
			placeHolder++;
		}
	}

	// Finds character that is most likely to appear at each position
	vector<pair<int,int>> charFreqPairs;
	for( int i=0; i<numChars; i++ )
	{
		charFreqPairs.push_back( make_pair( charProb[i], i ) );
	}
	sort( charFreqPairs.rbegin(), charFreqPairs.rend() );
	vector<pair<int,int>>::iterator i;
	i = charFreqPairs.begin();


	key += (char)(charOffset + i->second);
}

// Gets the number of characters that need to be switched to make s1=s2
// Uses the Levenshtein distance algorithm
int Decrypt::distance( string s1, string s2 )
{
	int size1 = s1.size() + 1;
	int size2 = s2.size() + 1;
	vector<vector<int>> distanceMatrix ( size1, vector<int>(size2) );
	distanceMatrix[0][0] = 0;
	for( int i=1; i<size1; i++ )
	{
		distanceMatrix[i][0] = i;
	}
	for( int i=1; i<size1; i++ )
	{
		distanceMatrix[0][i] = i;
	}
	// Loop through rows
	for( int r=1; r<size1; r++ )
	{
		// Loop through columns
		for( int c=1; c<size2; c++ ) // Yes, I just put c++ in my c++ code
		{
			// Check if each character matches, if so, distance stays the same
			// Otherwise, distance gets incremented and the incremenet flows through matrix
			distanceMatrix[r][c] = min( min( distanceMatrix[r-1][c]+1, distanceMatrix[r][c-1]+1 ), distanceMatrix[r-1][c-1] + (s1[r-1]==s2[c-1] ? 0:1) );
		}
	}
	return distanceMatrix[size1-1][size2-1];
}

void Decrypt::guessPlaintext()
{
	cout << "Guessing plaintext" << endl;
	
	// Use a map to find string with shortest distance
	map<int,string> matches;

	// Initial guess
	string plaintext = ciphertext;
	int keyOffset = 0;

	// Loop through ciphertext and update the plaintext according to the most
	// probable plaintext, considering the ciphertext and probable key
	for( int i=0; i<ciphertextLen; i++ )
	{
		plaintext[i]=char(((  ((int)ciphertext[i]-charOffset)-  ((int)key[keyOffset % keyLen]-charOffset)  +numChars)%numChars)+charOffset);
		keyOffset++;
	}

	// Loop through string that contains dictionary
	int dictPtr = 0;
	int dictPos = ciphertextLen;
	while( dictPos < (int)dictionary1.size()+1 )
	{
		// Check one line worth of data
		string curLine = dictionary1.substr( dictPtr, ciphertextLen );
		// Check if it matches the data in the ciphertext
		matches[ distance( curLine, plaintext) ] = curLine;
		dictPtr++;
		dictPos++;
	}
	map<int, string>::iterator iter = matches.begin();
	plaintext = iter->second;

	// Replace the '`' with the character it should have been, ' '
	replace( plaintext.begin(), plaintext.end(), '`', ' ');
	cout << "Plaintext:" << endl << plaintext << endl;
}


int main()
{
	Decrypt dec;
	dec.decryptor();
	system("pause");
}
