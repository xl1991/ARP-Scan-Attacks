package ArpAttack;
import java.util.HashMap;

public class Solution {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		HashMap<String, String> map = new HashMap<String, String>();
		map = new ArpImplenment().GetAllMacAddress();
		ArpImplenment.SendArp(map);
	}
}
